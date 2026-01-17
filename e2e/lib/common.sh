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
  # Output to stderr so logs don't pollute stdout when capturing function return values
  printf '%s %s\n' "$E2E_LOG_PREFIX" "$*" >&2
}

log_error() {
  printf '%s ERROR: %s\n' "$E2E_LOG_PREFIX" "$*" >&2
}

log_warn() {
  printf '%s WARN: %s\n' "$E2E_LOG_PREFIX" "$*" >&2
}

log_debug() {
  if [ "${E2E_DEBUG:-false}" = "true" ]; then
    # Output to stderr so debug logs don't pollute stdout
    printf '%s DEBUG: %s\n' "$E2E_LOG_PREFIX" "$*" >&2
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
TMUX_DEBUG_IMAGE=${TMUX_DEBUG_IMAGE:-breakglass-tmux-debug:latest}
TMUX_DEBUG_IMAGE_DIR=${TMUX_DEBUG_IMAGE_DIR:-${E2E_DIR:-}/images/tmux-debug}

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
  
  log "Waiting for HTTP endpoint $description (URL: $url, max ${max_attempts}s)..."
  for i in $(seq 1 "$max_attempts"); do
    # Try to reach the endpoint
    local response
    local exit_code
    response=$(curl $curl_opts -w "\nHTTP_CODE:%{http_code}" "$url" 2>&1) && exit_code=0 || exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
      log "$description is available (after ${i}s)"
      return 0
    fi
    
    # Early diagnostic after 10 seconds if not responding
    if [ "$i" -eq 10 ]; then
      log_warn "$description not responding after 10 seconds. Running diagnostics..."
      log_debug "curl exit code: $exit_code, response: ${response:0:500}"
      # Show what we're trying to connect to
      local parsed_host
      parsed_host=$(echo "$url" | sed -E 's#https?://([^:/]+).*#\1#')
      log_debug "Checking connectivity to $parsed_host..."
      # All diagnostic output MUST go to stderr to avoid polluting function return values
      { ping -c 2 "$parsed_host" 2>&1 || echo "Ping failed"; } >&2
      { nc -zv "$parsed_host" 8080 2>&1 || true; } >&2
      { nc -zv "$parsed_host" 8443 2>&1 || true; } >&2
    fi
    
    # Log progress periodically (every 10 attempts)
    if [ $((i % 10)) -eq 0 ]; then
      log "Still waiting for $description... (${i}/${max_attempts}s, exit code: $exit_code)"
    fi
    sleep 1
  done
  
  log_error "$description not available after $max_attempts attempts"
  # Final debug output (MUST go to stderr to avoid polluting function return values)
  log "Final curl attempt output:"
  { curl -v --connect-timeout 5 --max-time 10 "$url" 2>&1 | tail -30 || true; } >&2
  return 1
}

# ============================================================================
# DOCKER IMAGE HANDLING
# ============================================================================

# Pull image if not present locally (with retry for transient network issues)
ensure_image_exists() {
  local image="$1"
  local max_retries=3
  local retry_delay=5
  
  if ! $DOCKER image inspect "$image" >/dev/null 2>&1; then
    log "Docker image $image not found locally; pulling..."
    local attempt=1
    while [[ $attempt -le $max_retries ]]; do
      if $DOCKER pull "$image" 2>&1; then
        return 0
      fi
      if [[ $attempt -lt $max_retries ]]; then
        log_warn "Pull attempt $attempt/$max_retries failed for $image, retrying in ${retry_delay}s..."
        sleep $retry_delay
      fi
      ((attempt++))
    done
    log_error "Failed to pull image $image after $max_retries attempts"
    return 1
  fi
  return 0
}

# Build tmux-enabled debug image when needed (used by terminal-sharing tests)
ensure_tmux_debug_image() {
  local image="$TMUX_DEBUG_IMAGE"
  if $DOCKER image inspect "$image" >/dev/null 2>&1; then
    return 0
  fi
  if [ -z "$TMUX_DEBUG_IMAGE_DIR" ] || [ ! -f "$TMUX_DEBUG_IMAGE_DIR/Dockerfile" ]; then
    log_error "TMUX debug image Dockerfile not found at $TMUX_DEBUG_IMAGE_DIR/Dockerfile"
    return 1
  fi
  log "Building tmux debug image $image from $TMUX_DEBUG_IMAGE_DIR"
  $DOCKER build -t "$image" -f "$TMUX_DEBUG_IMAGE_DIR/Dockerfile" "$TMUX_DEBUG_IMAGE_DIR"
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
  local keycloak_image="${3:-quay.io/keycloak/keycloak:26.5.0}"
  
  log "Loading standard images into cluster $cluster_name..."
  
  e2e_load_image_into_kind "$cluster_name" "$breakglass_image"
  e2e_load_image_into_kind "$cluster_name" "$keycloak_image"
  e2e_load_image_into_kind "$cluster_name" "mailhog/mailhog:v1.0.1"
  e2e_load_image_into_kind "$cluster_name" "curlimages/curl:8.4.0"
  e2e_load_image_into_kind "$cluster_name" "nicolaka/netshoot"
  e2e_load_image_into_kind "$cluster_name" "apache/kafka:3.7.0"
  e2e_load_image_into_kind "$cluster_name" "python:3.11-slim"
  ensure_tmux_debug_image
  e2e_load_image_into_kind "$cluster_name" "$TMUX_DEBUG_IMAGE"
  
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
  local namespace="${3:-breakglass-system}"
  
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
    "breakglass-webhook-service.$namespace.svc"
    "breakglass-webhook-service.$namespace.svc.cluster.local"
    # Manager service
    "breakglass-manager.$namespace.svc"
    "breakglass-manager.$namespace.svc.cluster.local"
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
  local namespace="${3:-breakglass-system}"
  
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
    "breakglass-keycloak"
    "breakglass-keycloak.$namespace"
    "breakglass-keycloak.$namespace.svc"
    "breakglass-keycloak.$namespace.svc.cluster.local"
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

# Capture Kind cluster logs before deletion (for debugging failures)
capture_kind_logs_on_failure() {
  local cluster_name="$1"
  local output_dir="${2:-/tmp/kind-failure-logs}"
  
  log_error "Capturing logs for failed cluster $cluster_name to $output_dir"
  mkdir -p "$output_dir"
  
  # Capture container logs via docker
  local container_name="${cluster_name}-control-plane"
  if docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
    log "Capturing docker logs for $container_name..."
    docker logs "$container_name" > "$output_dir/${container_name}-docker.log" 2>&1 || true
    
    # Try to get kubelet/apiserver logs from container
    log "Capturing kubelet journal from $container_name..."
    docker exec "$container_name" journalctl -u kubelet --no-pager > "$output_dir/${container_name}-kubelet.log" 2>&1 || true
    
    # Capture container filesystem state
    log "Capturing kubernetes manifests from $container_name..."
    docker exec "$container_name" ls -la /etc/kubernetes/manifests/ > "$output_dir/${container_name}-manifests-list.txt" 2>&1 || true
    docker exec "$container_name" cat /etc/kubernetes/manifests/kube-apiserver.yaml > "$output_dir/${container_name}-apiserver-manifest.yaml" 2>&1 || true
    
    # Capture crictl container status
    log "Capturing crictl container status..."
    docker exec "$container_name" crictl ps -a > "$output_dir/${container_name}-crictl-ps.txt" 2>&1 || true
    docker exec "$container_name" crictl logs "$(docker exec "$container_name" crictl ps -a --name kube-apiserver -q 2>/dev/null | head -1)" > "$output_dir/${container_name}-apiserver.log" 2>&1 || true
  fi
  
  log_error "Failure logs captured to $output_dir"
  log_error "Contents:"
  ls -la "$output_dir" >&2 || true
}

# Create a Kind cluster
# Environment variables:
#   KIND_RETAIN_ON_FAILURE=true  - Keep cluster nodes on failure for debugging
#   KIND_FAILURE_LOG_DIR=<path>  - Directory to capture failure logs (default: /tmp/kind-failure-logs)
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
  
  # Build kind create command with optional --retain flag
  local kind_create_args=(create cluster --name "$cluster_name" --config "$config_file" --wait "$wait_time")
  
  # Add --retain flag to keep nodes on failure for debugging
  if [ "${KIND_RETAIN_ON_FAILURE:-false}" = "true" ]; then
    log "KIND_RETAIN_ON_FAILURE=true: Nodes will be preserved on failure for debugging"
    kind_create_args+=(--retain)
  fi
  
  log "Creating Kind cluster $cluster_name..."
  if ! $KIND "${kind_create_args[@]}"; then
    local exit_code=$?
    log_error "Kind cluster creation failed for $cluster_name (exit code: $exit_code)"
    
    # Capture logs before potential cleanup
    local log_dir="${KIND_FAILURE_LOG_DIR:-/tmp/kind-failure-logs}/${cluster_name}"
    capture_kind_logs_on_failure "$cluster_name" "$log_dir"
    
    if [ "${KIND_RETAIN_ON_FAILURE:-false}" = "true" ]; then
      log_error "Cluster nodes retained for debugging. To clean up manually run:"
      log_error "  kind delete cluster --name $cluster_name"
      log_error "  docker rm -f ${cluster_name}-control-plane"
    fi
    
    return $exit_code
  fi
  
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
  local namespace="${3:-breakglass-system}"
  
  log "Injecting hub service hostnames into $spoke_node..."
  
  local hostnames=(
    # Breakglass service hostnames
    "breakglass-manager.$namespace.svc.cluster.local"
    "breakglass-webhook-service.$namespace.svc.cluster.local"
    "breakglass-external.$namespace.svc.cluster.local"
    # Keycloak service hostnames
    "breakglass-keycloak.$namespace.svc.cluster.local"
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
  local namespace="${3:-breakglass-system}"
  
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
  
  # Collect namespace-level events for deployments
  log "--- Events in breakglass-system ---"
  KUBECONFIG="$kubeconfig" $KUBECTL get events -n breakglass-system --sort-by='.lastTimestamp' 2>&1 | tail -50 || true
  
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
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.5.0}
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
  # Remaining arguments are realm JSON files to import
  shift 2 || true
  local realm_files=("$@")
  
  log "Starting Keycloak container (function called)..."
  log "Parameters: tls_dir=$tls_dir, network=$network, realm_files=${realm_files[*]:-none}"
  log "Image: $KEYCLOAK_IMAGE, Container name: $KEYCLOAK_CONTAINER_NAME"
  
  # Ensure the network exists (Kind creates it when first cluster starts,
  # but we may need it before that)
  if ! $DOCKER network inspect "$network" >/dev/null 2>&1; then
    log "Creating Docker network '$network'..."
    # Redirect stdout to /dev/null - network create outputs network ID which pollutes function return
    $DOCKER network create "$network" >/dev/null || {
      log_error "Failed to create Docker network '$network'"
      return 1
    }
  fi
  
  # Remove existing container if present
  if $DOCKER ps -a --filter "name=$KEYCLOAK_CONTAINER_NAME" -q 2>/dev/null | grep -q .; then
    log "Removing existing Keycloak container..."
    $DOCKER rm -f "$KEYCLOAK_CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  
  log "Building docker run command..."
  # Build the docker run command
  local docker_args=(
    run -d
    --name "$KEYCLOAK_CONTAINER_NAME"
    --network "$network"
    -e "KC_BOOTSTRAP_ADMIN_USERNAME=$KEYCLOAK_ADMIN_USER"
    -e "KC_BOOTSTRAP_ADMIN_PASSWORD=$KEYCLOAK_ADMIN_PASS"
    -e "KC_HOSTNAME_STRICT=false"
    -e "KC_HOSTNAME_STRICT_HTTPS=false"
    -e "KC_HTTP_ENABLED=true"
    -e "KC_LOG_LEVEL=DEBUG"
  )
  log "Base docker args configured"
  
  # Add TLS configuration (REQUIRED for proper HTTPS support)
  if [ -n "$tls_dir" ]; then
    if [ ! -f "$tls_dir/tls.crt" ] || [ ! -f "$tls_dir/tls.key" ]; then
      log_error "TLS directory specified but certificate files are missing"
      log_error "  Directory: $tls_dir"
      log_error "  Cert exists: $([ -f "$tls_dir/tls.crt" ] && echo yes || echo no)"
      log_error "  Key exists: $([ -f "$tls_dir/tls.key" ] && echo yes || echo no)"
      log "Directory contents:"
      ls -la "$tls_dir" 2>&1 || true
      return 1
    fi
    
    # Verify files are readable and not empty
    if [ ! -s "$tls_dir/tls.crt" ] || [ ! -s "$tls_dir/tls.key" ]; then
      log_error "TLS certificate files exist but are empty"
      log_error "  Cert size: $(wc -c < "$tls_dir/tls.crt" 2>/dev/null || echo 0) bytes"
      log_error "  Key size: $(wc -c < "$tls_dir/tls.key" 2>/dev/null || echo 0) bytes"
      return 1
    fi
    
    log "Configuring Keycloak with TLS from $tls_dir"
    log "  TLS cert: $(wc -c < "$tls_dir/tls.crt") bytes"
    log "  TLS key: $(wc -c < "$tls_dir/tls.key") bytes"
    
    # Use absolute paths for volume mounts
    # Mount at /etc/x509/https/ to match Kubernetes deployment configuration
    # Note: Adding :z suffix for SELinux contexts to allow container access
    local abs_tls_dir
    abs_tls_dir=$(cd "$tls_dir" && pwd)
    
    docker_args+=(
      -v "$abs_tls_dir/tls.crt:/etc/x509/https/tls.crt:ro,z"
      -v "$abs_tls_dir/tls.key:/etc/x509/https/tls.key:ro,z"
      -e "KC_HTTPS_CERTIFICATE_FILE=/etc/x509/https/tls.crt"
      -e "KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/x509/https/tls.key"
    )
    log "TLS configuration added with absolute paths and SELinux context (matching K8s deployment)"
  else
    log_warn "No TLS directory specified - Keycloak will use HTTP only"
    log_warn "This is NOT recommended for production or proper OIDC testing"
  fi
  
  # Expose ports on host (for local testing)
  log "Adding port mappings: ${KEYCLOAK_HTTP_PORT}:8080, ${KEYCLOAK_HTTPS_PORT}:8443"
  docker_args+=(
    -p "${KEYCLOAK_HTTP_PORT}:8080"
    -p "${KEYCLOAK_HTTPS_PORT}:8443"
  )
  log "Port mappings added"
  
  # Add realm import volumes if realm JSON files are provided
  local keycloak_args=("start-dev")
  if [ ${#realm_files[@]} -gt 0 ]; then
    local realm_count=0
    for realm_json in "${realm_files[@]}"; do
      if [ -n "$realm_json" ] && [ -f "$realm_json" ]; then
        local abs_realm_json
        abs_realm_json=$(cd "$(dirname "$realm_json")" && pwd)/$(basename "$realm_json")
        local realm_filename
        realm_filename=$(basename "$realm_json")
        log "Mounting realm JSON for import: $abs_realm_json"
        docker_args+=(
          -v "$abs_realm_json:/opt/keycloak/data/import/$realm_filename:ro,z"
        )
        realm_count=$((realm_count + 1))
      else
        log_warn "Realm file not found, skipping: $realm_json"
      fi
    done
    if [ $realm_count -gt 0 ]; then
      keycloak_args+=("--import-realm")
      log "Configured import of $realm_count realm(s)"
    fi
  fi
  
  # Add image and command
  docker_args+=(
    "$KEYCLOAK_IMAGE"
    "${keycloak_args[@]}"
  )
  
  log "Running: docker ${docker_args[*]}"
  log "Docker command about to execute..."
  local container_id
  local docker_exit_code
  local docker_output
  
  # Pull image first to avoid stdout pollution from pull messages
  # Docker pull output goes to stderr, so we redirect to show progress but not capture
  log "Ensuring Keycloak image is available (pulling if needed)..."
  $DOCKER pull "$KEYCLOAK_IMAGE" >&2 2>&1 || true
  
  # Now run container - stdout will only contain the container ID
  docker_output=$($DOCKER "${docker_args[@]}" 2>&1) && docker_exit_code=0 || docker_exit_code=$?
  
  # Extract container ID (should be the last line, a 64-char hex string)
  # This handles cases where there might be extra output
  container_id=$(echo "$docker_output" | grep -oE '^[a-f0-9]{64}$' | tail -1)
  if [ -z "$container_id" ]; then
    # Fallback: just use the last line
    container_id=$(echo "$docker_output" | tail -1)
  fi
  
  log "Docker command completed with exit code: $docker_exit_code"
  
  if [ $docker_exit_code -ne 0 ]; then
    log_error "Failed to start Keycloak container (exit code: $docker_exit_code)"
    log "Docker error output: $docker_output"
    log "Docker version: $($DOCKER --version)"
    log "Docker info (brief): $($DOCKER info 2>&1 | head -20)"
    log "=== Checking if container was created but failed to start ==="
    $DOCKER ps -a --filter "name=$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
    if $DOCKER ps -a --filter "name=$KEYCLOAK_CONTAINER_NAME" -q 2>/dev/null | grep -q .; then
      log "Container exists but in failed state. Logs:"
      $DOCKER logs "$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
    fi
    return 1
  fi
  
  log "Keycloak container started with ID: $container_id"
  log "=== Initial container status (immediate) ==="
  $DOCKER ps --filter "name=$KEYCLOAK_CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" >&2 2>&1 || true
  
  # Wait for Keycloak to be ready
  log "Waiting for Keycloak to start..."
  
  # Give container initial startup time and verify it stays running
  log "Waiting 3 seconds for container initialization..."
  sleep 3
  
  # Verify container is running
  if ! is_keycloak_running; then
    log_error "Keycloak container is not running after 3 seconds"
    log "=== Container status ==="
    $DOCKER ps -a --filter "name=$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
    log "=== Container logs (all) ==="
    $DOCKER logs "$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
    log "=== Docker inspect (full) ==="
    $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
    log "=== Docker inspect (mounts) ==="
    { $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Mounts}}' 2>&1 | python3 -m json.tool 2>/dev/null || $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Mounts}}' 2>&1 || true; } >&2
    log "=== Docker inspect (config/env) ==="
    { $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Config.Env}}' 2>&1 | python3 -m json.tool 2>/dev/null || $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Config.Env}}' 2>&1 || true; } >&2
    log "=== Docker inspect (state) ==="
    { $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .State}}' 2>&1 | python3 -m json.tool 2>/dev/null || $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .State}}' 2>&1 || true; } >&2
    log "=== Port check ==="
    { netstat -tlnp 2>/dev/null | grep -E "${KEYCLOAK_HTTP_PORT}|${KEYCLOAK_HTTPS_PORT}" || ss -tlnp 2>/dev/null | grep -E "${KEYCLOAK_HTTP_PORT}|${KEYCLOAK_HTTPS_PORT}" || echo "No listeners on configured ports"; } >&2
    return 1
  fi
  
  # Check again after another 2 seconds to ensure it stays running
  log "Container is running, waiting another 2 seconds to ensure stability..."
  sleep 2
  
  if ! is_keycloak_running; then
    log_error "Keycloak container started but then died within 5 seconds"
    log "This typically indicates a configuration error (e.g., missing TLS files inside container)"
    log "=== Container exit status ==="
    $DOCKER ps -a --filter "name=$KEYCLOAK_CONTAINER_NAME" --format "{{.Status}}" >&2 2>&1 || true
    log "=== Container logs (all) ==="
    $DOCKER logs "$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
    log "=== Docker inspect (mounts and env) ==="
    { $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Mounts}}' 2>&1 | python3 -m json.tool 2>/dev/null || $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Mounts}}' 2>&1 || true; } >&2
    { $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Config.Env}}' 2>&1 | python3 -m json.tool 2>/dev/null || $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Config.Env}}' 2>&1 || true; } >&2
    log "=== Docker inspect (state details) ==="
    { $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .State}}' 2>&1 | python3 -m json.tool 2>/dev/null || $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .State}}' 2>&1 || true; } >&2
    log "=== Docker inspect (full for debugging) ==="
    $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
    return 1
  fi
  
  # Verify TLS files are accessible inside the container
  if [ -n "$tls_dir" ]; then
    log "Verifying TLS files inside container..."
    if ! $DOCKER exec "$KEYCLOAK_CONTAINER_NAME" ls -l /etc/x509/https/tls.crt /etc/x509/https/tls.key >&2 2>&1; then
      log_error "TLS files not accessible inside container"
      return 1
    fi
    log "TLS files are accessible inside container"
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
  $DOCKER port "$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
  
  # Wait for HTTP endpoint - use localhost with mapped port as the container IP
  # may not be routable from the host in CI environments (GitHub Actions)
  log "Checking Keycloak readiness via localhost:${KEYCLOAK_HTTP_PORT} (mapped port)"
  # Increase timeout to 300 seconds (5 minutes) for slow CI environments and GitHub Actions runners
  # Note: Keycloak 23.0.0 in dev mode doesn't expose /health/ready endpoint by default
  # We check the realms endpoint instead as it indicates Keycloak is fully initialized
  
  # Check container logs before waiting to see if there are early errors
  log "=== Keycloak container logs (first 20 lines after start) ==="
  { $DOCKER logs "$KEYCLOAK_CONTAINER_NAME" 2>&1 | head -20 || log_warn "Could not get initial container logs"; } >&2
  
  if ! wait_for_http "http://localhost:${KEYCLOAK_HTTP_PORT}/realms/master" 300 "Keycloak master realm"; then
    log_error "Keycloak failed to become ready on localhost:${KEYCLOAK_HTTP_PORT}"
    log "=== Keycloak container status ==="
    $DOCKER ps -a --filter "name=$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
    log "=== Keycloak container full logs ==="
    $DOCKER logs "$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
    log "=== Docker inspect (mounts and config) ==="
    { $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Mounts}}' 2>&1 | head -50 || true; } >&2
    { $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{json .Config}}' 2>&1 | head -50 || true; } >&2
    log "=== Port bindings on host ==="
    { netstat -tlnp 2>/dev/null | grep -E "8080|8443" || ss -tlnp 2>/dev/null | grep -E "8080|8443" || echo "Could not check ports"; } >&2
    log "=== Testing localhost connectivity ==="
    { curl -v "http://localhost:${KEYCLOAK_HTTP_PORT}/" 2>&1 | head -30 || true; } >&2
    
    log "Trying container IP as fallback: http://${keycloak_ip}:8080/realms/master"
    if ! wait_for_http "http://${keycloak_ip}:8080/realms/master" 120 "Keycloak master realm (container IP)"; then
      log_error "Keycloak failed to become ready via container IP as well"
      log "=== Final diagnostics before failure ==="
      log "Container still running: $(is_keycloak_running && echo 'YES' || echo 'NO')"
      $DOCKER stats --no-stream "$KEYCLOAK_CONTAINER_NAME" >&2 2>&1 || true
      return 1
    fi
    log "Keycloak is ready via container IP (not localhost) - this may cause issues with host-based tests"
  fi
  
  log "Keycloak is ready (container IP: ${keycloak_ip}, host port: ${KEYCLOAK_HTTP_PORT})"
  
  # Final verification: Test HTTPS endpoint if TLS is configured
  if [ -n "$tls_dir" ]; then
    log "Testing HTTPS endpoint..."
    if curl -sk --connect-timeout 5 "https://localhost:${KEYCLOAK_HTTPS_PORT}/realms/master" >/dev/null 2>&1; then
      log "HTTPS endpoint is accessible on port ${KEYCLOAK_HTTPS_PORT}"
    else
      log_warn "HTTPS endpoint not accessible on port ${KEYCLOAK_HTTPS_PORT}, but container is running"
      log "Checking if port is mapped..."
      { $DOCKER port "$KEYCLOAK_CONTAINER_NAME" 2>&1 | grep 8443 || log_warn "Port 8443 not mapped"; } >&2
    fi
  fi
  
  # Return ONLY the keycloak IP - all diagnostic output goes to stderr
  echo "$keycloak_ip"
}

# Stop and remove Keycloak container
# Respects PRESERVE_ON_FAILURE and SCRIPT_FAILED environment variables for diagnostics
stop_keycloak_container() {
  # Skip cleanup if PRESERVE_ON_FAILURE is set and script failed
  if [ "${PRESERVE_ON_FAILURE:-false}" = "true" ] && [ "${SCRIPT_FAILED:-false}" = "true" ]; then
    log "PRESERVE_ON_FAILURE=true and script failed - preserving Keycloak container for diagnostics"
    log "Container name: $KEYCLOAK_CONTAINER_NAME"
    return 0
  fi
  
  log "Stopping Keycloak container..."
  $DOCKER rm -f "$KEYCLOAK_CONTAINER_NAME" >/dev/null 2>&1 || true
}

# Configure Keycloak realm - wait for realm import to complete
# All users, groups, and clients are defined in breakglass-e2e-realm.json and breakglass-e2e-contractors-realm.json
# This function only waits for the realm to be available after import
configure_keycloak_realm() {
  local realm="${1:-$KEYCLOAK_REALM}"
  local keycloak_url="${2:-http://$(get_keycloak_ip):8080}"
  
  log "Waiting for Keycloak realm '$realm' to be ready..."
  
  # Verify Keycloak container is running
  if ! is_keycloak_running; then
    log_error "Keycloak container is not running, cannot configure realm"
    return 1
  fi
  
  # Wait for realm to be available (imported from JSON)
  log "Waiting for Keycloak realm '$realm' to be available..."
  local max_wait=60
  local count=0
  while [ $count -lt $max_wait ]; do
    # Check if realm exists by trying to get a token
    # Use breakglass-ui client which is defined in breakglass-e2e-realm.json
    if curl -s -f -X POST "$keycloak_url/realms/$realm/protocol/openid-connect/token" \
        -d "client_id=breakglass-ui" \
        -d "username=test-user" \
        -d "password=test-password" \
        -d "grant_type=password" 2>/dev/null | grep -q "access_token"; then
      log "Keycloak realm '$realm' is ready"
      return 0
    fi
    count=$((count + 1))
    if [ $((count % 10)) -eq 0 ]; then
      log "Still waiting for realm '$realm'... ($count/$max_wait)"
    fi
    sleep 1
  done
  
  log_error "Keycloak realm '$realm' did not become ready within ${max_wait}s"
  log "Keycloak container logs:"
  $DOCKER logs "$KEYCLOAK_CONTAINER_NAME" 2>&1 | tail -100
  return 1
}

# Generate TLS certificates for Keycloak container
generate_keycloak_container_tls() {
  local output_dir="$1"
  local keycloak_container_name="${2:-$KEYCLOAK_CONTAINER_NAME}"
  # Additional IPs to include in SANs (space-separated)
  local additional_ips="${3:-}"
  
  log "Generating TLS certificates for Keycloak container..."
  mkdir -p "$output_dir"
  
  # Generate CA if not exists
  if [ ! -f "$output_dir/ca.crt" ]; then
    log "Generating CA certificate..."
    generate_ca_cert "$output_dir" "keycloak-ca"
    if [ ! -f "$output_dir/ca.crt" ]; then
      log_error "Failed to generate CA certificate at $output_dir/ca.crt"
      return 1
    fi
    log "CA certificate generated successfully"
  else
    log "Using existing CA certificate at $output_dir/ca.crt"
  fi
  
  # SANs for Keycloak container
  # Include a range of likely Docker IPs to handle dynamic allocation
  # Docker kind network typically starts at 172.18.0.2 for containers
  local sans=(
    "$keycloak_container_name"
    "keycloak"
    "localhost"
    "127.0.0.1"
    # Include common Docker network IPs for multi-cluster setups
    "172.18.0.2"
    "172.18.0.3"
    "172.18.0.4"
    "172.18.0.5"
  )
  
  # Add any additional IPs passed as parameter
  if [ -n "$additional_ips" ]; then
    for ip in $additional_ips; do
      sans+=("$ip")
    done
  fi
  
  log "Generating server certificate for $keycloak_container_name with SANs: ${sans[*]}"
  generate_server_cert "$output_dir" "$keycloak_container_name" "${sans[@]}"
  
  # Verify all required files exist
  local required_files=("$output_dir/ca.crt" "$output_dir/tls.crt" "$output_dir/tls.key")
  for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
      log_error "Required TLS file missing: $file"
      log "Directory contents:"
      ls -la "$output_dir" || true
      return 1
    fi
    if [ ! -s "$file" ]; then
      log_error "Required TLS file is empty: $file"
      return 1
    fi
    log "Verified TLS file: $file ($(wc -c < "$file") bytes)"
  done
  
  # Set proper permissions
  # Note: Using 644 for tls.key (instead of 600) to ensure it's readable when mounted
  # into containers where the process runs as a different user (e.g., keycloak user)
  chmod 644 "$output_dir/tls.crt" "$output_dir/ca.crt" "$output_dir/tls.key" 2>/dev/null || true
  
  log "Keycloak TLS certificates generated successfully at $output_dir"
  log "Contents:"
  ls -lh "$output_dir" || true
  
  # Validate certificates with openssl if available
  if command -v openssl >/dev/null 2>&1; then
    log "Validating certificate with openssl..."
    if openssl x509 -in "$output_dir/tls.crt" -noout -text 2>&1 | head -15; then
      log "Certificate is valid"
      # Show expiration
      local expiry
      expiry=$(openssl x509 -in "$output_dir/tls.crt" -noout -enddate 2>&1)
      log "Certificate expiry: $expiry"
    else
      log_error "Certificate validation failed"
      return 1
    fi
    
    # Verify key matches cert
    local cert_modulus key_modulus
    cert_modulus=$(openssl x509 -noout -modulus -in "$output_dir/tls.crt" 2>&1 | openssl md5)
    key_modulus=$(openssl rsa -noout -modulus -in "$output_dir/tls.key" 2>&1 | openssl md5)
    if [ "$cert_modulus" = "$key_modulus" ]; then
      log "Certificate and key match (verified via modulus)"
    else
      log_error "Certificate and key do NOT match!"
      log "Cert modulus: $cert_modulus"
      log "Key modulus: $key_modulus"
      return 1
    fi
  else
    log_warn "openssl not available, skipping certificate validation"
  fi
  
  return 0
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
  # Use HTTPS with port 8443 - CRD validation requires HTTPS for issuer/authority URLs
  issuer_url=$(get_keycloak_issuer_url "$realm" "$keycloak_host" "8443" "https")
  
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
