#!/usr/bin/env bash
set -euo pipefail
# Single-cluster variant: Keycloak + Breakglass controller + webhook auth all in one kind cluster.
# Replaces previous hub+tenant topology by creating only one cluster and using a ClusterConfig
# that points back to the same cluster (simulated tenant "tenant-a").

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
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:23.0.0}

# --- Cluster / service names (defaults kept from original script) ---
CLUSTER_NAME=${CLUSTER_NAME:-breakglass-hub}
WEBHOOK_HOST_PLACEHOLDER=${WEBHOOK_HOST_PLACEHOLDER:-breakglass.system.svc.cluster.local} # in-cluster service DNS

# --- Ports / forwards ---
NODEPORT=${NODEPORT:-31081}                 # NodePort used to expose the breakglass service for local tests
WEBHOOK_SERVICE_PORT=${WEBHOOK_SERVICE_PORT:-8081} # in-cluster port webhook/controller listens on
# Forward Keycloak HTTPS (container uses 8443) by default so local https access matches container port
KEYCLOAK_SVC_PORT=${KEYCLOAK_SVC_PORT:-8443}     # keycloak service internal port (prefer HTTPS)
KEYCLOAK_FORWARD_PORT=${KEYCLOAK_FORWARD_PORT:-8443} # local port forwarded to Keycloak svc:8443
CONTROLLER_FORWARD_PORT=${CONTROLLER_FORWARD_PORT:-28081} # local port forwarded to controller svc:8080
MAILHOG_UI_PORT=${MAILHOG_UI_PORT:-8025}

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
# (the dev overlay uses a namePrefix breakglass-dev- and namespace breakglass-dev-system).
# This ensures the apiserver OIDC issuer points at a DNS name resolvable inside the cluster.
KEYCLOAK_HOST=${KEYCLOAK_HOST:-breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local}
KEYCLOAK_HTTPS_PORT=${KEYCLOAK_HTTPS_PORT:-8443}
KEYCLOAK_REALM=${KEYCLOAK_REALM:-breakglass-e2e}

# --- Tenants / cluster ids used in rendered CRs ---
TENANT_A=${TENANT_A:-tenant-a}
TENANT_B=${TENANT_B:-tenant-b}
CLUSTER_CONFIG_ID=${CLUSTER_CONFIG_ID:-$CLUSTER_NAME}

# --- Proxy: locked to corporate HTTP proxy (do NOT allow overrides) ---
# As requested, force the proxies to the fixed value used in this environment.
HTTP_PROXY="http://172.17.0.1:8118"
HTTPS_PROXY="http://172.17.0.1:8118"
# Also export lowercase variants for tools that read them
http_proxy="http://172.17.0.1:8118"
https_proxy="http://172.17.0.1:8118"

# Ensure corporate proxy doesn't intercept in-cluster / localhost calls
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
if [ -n "${HTTP_PROXY:-${http_proxy:-}}" ] || [ -n "${HTTPS_PROXY:-${https_proxy:-}}" ]; then
  printf '[single-e2e] Using proxy but NO_PROXY set to: %s\n' "$NO_PROXY"
fi

log(){ printf '[single-e2e] %s\n' "$*"; }

# Fail fast if a manifest contains unreplaced placeholder-like tokens (e.g. NAME_PLACEHOLDER, TENANT_B_TEAM)
ensure_no_placeholders() {
  local file="$1"
  if [ ! -f "$file" ]; then
    # nothing to check
    return 0
  fi
  if grep -Eq '\$\{[A-Z0-9_]+\}|REPLACE_' "$file"; then
    printf '[single-e2e] ERROR: manifest %s contains unreplaced placeholder-like tokens.\n' "$file" >&2
    printf '[single-e2e] Matching lines:\n' >&2
    grep -En '\$\{[A-Z0-9_]+\}|REPLACE_' "$file" >&2 || true
    printf '[single-e2e] Please render the manifest (use RenderAndApplyManifest in tests or replace placeholders) before applying.\n' >&2
    exit 1
  fi
}

# --- Helper functions to reduce duplication ---
load_image_into_kind() {
  # Usage: load_image_into_kind imageName
  local img="$1"
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    log "Docker image $img not found locally; pulling"
    docker pull "$img" || true
  fi
  log "Loading image $img into kind cluster $CLUSTER_NAME"
  $KIND load docker-image "$img" --name "$CLUSTER_NAME" || true
}

wait_for_deploy_by_label() {
  # Usage: wait_for_deploy_by_label label max_attempts
  local label="$1"; local max_attempts=${2:-120}
  for i in $(seq 1 $max_attempts); do
    DEP_NS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy --all-namespaces -l app=${label} -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
    DEP_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy --all-namespaces -l app=${label} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [ -n "$DEP_NAME" ] && [ -n "$DEP_NS" ]; then
      log "Waiting rollout for $label: $DEP_NAME ns $DEP_NS"
      KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL rollout status deployment/"$DEP_NAME" -n "$DEP_NS" --timeout=240s && return 0
    fi
    sleep 2
  done
  return 1
}

start_port_forward() {
  # Usage: start_port_forward namespace svc localPort remotePort
  local ns="$1"; local svc="$2"; local local_port="$3"; local remote_port="$4"
  log "Starting port-forward for svc/$svc in ns $ns -> localhost:$local_port:$remote_port"
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$ns" port-forward svc/"$svc" ${local_port}:${remote_port} >/dev/null 2>&1 &
  local pid=$!
  [ -n "$PF_FILE" ] && mkdir -p "$(dirname "$PF_FILE")" || true
  echo $pid >> "$PF_FILE" || true
  echo $pid
}

apply_kustomize() {
  # Usage: apply_kustomize path
  local path="$1"
  log "Applying kustomize overlay: $path"
  KUBECONFIG="$HUB_KUBECONFIG" $KUSTOMIZE build "$path" | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
}

set_image_and_wait_by_label() {
  # Usage: set_image_and_wait_by_label label containerName image
  local label="$1"; local container="$2"; local image="$3"
  MANAGER_NS=$($KUBECTL get deploy --all-namespaces -l app=${label} -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
  MANAGER_NAME=$($KUBECTL get deploy --all-namespaces -l app=${label} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [ -n "$MANAGER_NAME" ] && [ -n "$MANAGER_NS" ]; then
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL set image deployment/"$MANAGER_NAME" -n "$MANAGER_NS" ${container}=${image} || true
    # wait for ready
    for i in {1..60}; do a=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy/"$MANAGER_NAME" -n "$MANAGER_NS" -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo 0); [ "$a" = "1" ] && break; sleep 3; done
    [ "$a" = "1" ] || { log "Deployment ${MANAGER_NAME} not ready"; return 1; }
  else
    log "Warning: deployment with label app=${label} not found; attempting fallback"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL set image deployment/manager -n system ${container}=${image} || true
    for i in {1..60}; do a=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy/manager -n system -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo 0); [ "$a" = "1" ] && break; sleep 3; done
    [ "$a" = "1" ] || { log 'Controller not ready'; return 1; }
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
DNS.7 = breakglass-dev-keycloak
DNS.8 = breakglass.system.svc.cluster.local
EOF
openssl genrsa -out "$TLS_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$TLS_DIR/ca.key" -subj "/CN=breakglass-keycloak-ca" -days 365 -out "$TLS_DIR/ca.crt"
openssl genrsa -out "$TLS_DIR/server.key" 2048
openssl req -new -key "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" -config "$OPENSSL_CONF_KEYCLOAK"
openssl x509 -req -in "$TLS_DIR/server.csr" -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial -out "$TLS_DIR/server.crt" -days 365 -extensions req_ext -extfile "$OPENSSL_CONF_KEYCLOAK"
cp "$TLS_DIR/ca.crt" "$KEYCLOAK_CA_FILE"

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
    unauthorizedTTL: 30s
    timeout: 3s
    subjectAccessReviewVersion: v1
    matchConditionSubjectAccessReviewVersion: v1
    failurePolicy: NoOpinion # Allow bootstrap to proceed if webhook unreachable
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: /etc/kubernetes/authorization-kubeconfig.yaml
    matchConditions:
    - expression: "!request.user.startsWith('system:')"
    - expression: "!request.groups.exists(g, g == 'system:serviceaccounts')"
    - expression: "request.groups.exists(g, g == 'system:authenticated')"
    - expression: "request.groups.exists(g, g.startsWith('oidc:')) || request.user.contains('@')"
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
cat > "$KIND_CFG" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta3
    kind: ClusterConfiguration
    metadata:
      name: config
    apiServer:
      extraArgs:
        authorization-config: /etc/kubernetes/authorization-config.yaml
        authentication-config: /etc/kubernetes/authentication-config.yaml
        feature-gates: StructuredAuthorizationConfiguration=true,StructuredAuthenticationConfiguration=true
        # Audit logging configuration: use the mounted audit policy and write audit logs to /var/log/kubernetes/audit.log
        audit-policy-file: /etc/kubernetes/audit-policy.yaml
        audit-log-path: /var/log/kubernetes/audit.log
        audit-log-maxage: "30"
        audit-log-maxbackup: "10"
        audit-log-maxsize: "100"
        v: "6"
      extraVolumes:
      - name: authorization-config
        hostPath: /etc/kubernetes/authorization-config.yaml
        mountPath: /etc/kubernetes/authorization-config.yaml
        pathType: FileOrCreate
      - name: authorization-kubeconfig
        hostPath: /etc/kubernetes/authorization-kubeconfig.yaml
        mountPath: /etc/kubernetes/authorization-kubeconfig.yaml
        pathType: FileOrCreate
      - name: authentication-config
        hostPath: /etc/kubernetes/authentication-config.yaml
        mountPath: /etc/kubernetes/authentication-config.yaml
        pathType: FileOrCreate
      - name: keycloak-ca
        hostPath: /etc/kubernetes/keycloak-ca.crt
        mountPath: /etc/kubernetes/keycloak-ca.crt
        pathType: FileOrCreate
      - name: audit-policy
        hostPath: /etc/kubernetes/audit-policy.yaml
        mountPath: /etc/kubernetes/audit-policy.yaml
        pathType: FileOrCreate
      - name: audit-log
        hostPath: /var/log/kubernetes/audit.log
        mountPath: /var/log/kubernetes/audit.log
        pathType: FileOrCreate
  extraPortMappings:
  - containerPort: ${NODEPORT}
    hostPort: ${NODEPORT}
    protocol: TCP
  extraMounts:
  - hostPath: $AUTHZ_FILE
    containerPath: /etc/kubernetes/authorization-config.yaml
  - hostPath: $AUTHN_FILE
    containerPath: /etc/kubernetes/authentication-config.yaml
  - hostPath: $WEBHOOK_KCFG
    containerPath: /etc/kubernetes/authorization-kubeconfig.yaml
  - hostPath: $KEYCLOAK_CA_FILE
    containerPath: /etc/kubernetes/keycloak-ca.crt
  - hostPath: $TDIR/audit-policy.yaml
    containerPath: /etc/kubernetes/audit-policy.yaml
  - hostPath: $TDIR/audit.log
    containerPath: /var/log/kubernetes/audit.log
EOF

if $KIND get clusters | grep -q "^${CLUSTER_NAME}$"; then log "Deleting existing ${CLUSTER_NAME}"; $KIND delete cluster --name "$CLUSTER_NAME" || true; fi
log "Creating single cluster ${CLUSTER_NAME} (image $KIND_NODE_IMAGE)"
$KIND create cluster --name "$CLUSTER_NAME" --image "$KIND_NODE_IMAGE" --config "$KIND_CFG" --wait 120s
$KIND get kubeconfig --name "$CLUSTER_NAME" > "$HUB_KUBECONFIG"

log 'Build & load controller image (respect UI_FLAVOUR build arg)'
docker build --build-arg UI_FLAVOUR="$UI_FLAVOUR" -t "$IMAGE" . >/dev/null
# load built images into kind node using helper
load_image_into_kind "$IMAGE"
load_image_into_kind "$KEYCLOAK_IMAGE"
load_image_into_kind "mailhog/mailhog:v1.0.1"
# Ensure the init container image (curl) is available in kind node to avoid unsupported manifest errors
load_image_into_kind "curlimages/curl:8.4.0"
# Preload netshoot so we can create a persistent debug pod without image pull delays
load_image_into_kind "nicolaka/netshoot"

log 'Deploy development stack via kustomize (config/dev)'
# Create TLS secret data for kustomize resources (if keycloak expects a secret, we create it first)
# Use the dev namespace kustomize writes to (namePrefix on config/dev is breakglass-dev- and namespace is breakglass-dev-system)
DEV_NS=breakglass-dev-system
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create namespace "$DEV_NS" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f - || true
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret tls keycloak-tls -n "$DEV_NS" --cert="$TLS_DIR/server.crt" --key="$TLS_DIR/server.key" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Create breakglass-dev-certs ConfigMap from generated CA so deployments mounting it succeed
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create configmap breakglass-dev-certs -n "$DEV_NS" --from-file=ca.crt="$TLS_DIR/ca.crt" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Apply the whole development overlay via kustomize so all resources come from config/dev
ensure_no_placeholders "config/dev/resources/keycloak.yaml"
# explicitly apply CRDs first
apply_kustomize config/crd

# Apply the dev overlay (creates config ConfigMap among other resources)
apply_kustomize config/dev

# Patch the generated config ConfigMap in-cluster to embed the generated CA so the
# running controller can validate Keycloak TLS. The configMap created by the kustomize
# overlay is namePrefix'd to 'breakglass-dev-config' in namespace $DEV_NS.
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
  name: breakglass-dev-config
  namespace: $DEV_NS
data:
  config.yaml: |
    server:
      listenAddress: 0.0.0.0:8080
    authorizationServer:
      url: https://breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local:8443
      jwksEndpoint: "realms/breakglass-e2e/protocol/openid-connect/certs"
      certificateAuthority: |
$CA_INLINE
    frontend:
      oidcAuthority: https://localhost:8443/realms/breakglass-e2e
      oidcClientID: breakglass-ui
      baseURL: http://localhost:${CONTROLLER_FORWARD_PORT}
    mail:
      host: breakglass-dev-mailhog.breakglass-dev-system.svc.cluster.local
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
  CFG_NAME=$($KUBECTL -n "$DEV_NS" get cm -o name 2>/dev/null | sed 's#configmap/##' | grep '^breakglass-dev-config' | head -n1 || true)
  if [ -n "$CFG_NAME" ]; then
    TARGET_NAME="$CFG_NAME"
    log "Detected rendered configmap name: $TARGET_NAME"
    break
  fi
  sleep 1
done
if [ -z "$TARGET_NAME" ]; then
  log "Could not detect rendered breakglass-dev-config name after wait; using base name breakglass-dev-config"
  TARGET_NAME=breakglass-dev-config
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
      url: https://breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local:8443
      jwksEndpoint: "realms/breakglass-e2e/protocol/openid-connect/certs"
      certificateAuthority: |
$CA_INLINE
    frontend:
      oidcAuthority: https://localhost:8443/realms/breakglass-e2e
      oidcClientID: breakglass-ui
      baseURL: http://localhost:${CONTROLLER_FORWARD_PORT}
    mail:
      host: breakglass-dev-mailhog.breakglass-dev-system.svc.cluster.local
      port: 1025
      insecureSkipVerify: true
    kubernetes:
      context: ""
      oidcPrefixes:
        - "keycloak:"
        - "oidc:"
EOF

KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f "$TMP_CFG" || log "Warning: failed to apply patched $TARGET_NAME"

# Apply example sample manifests so sample escalations/sessions are present in the cluster
log 'Applying sample manifests from config/samples'
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f config/samples/ || log 'Warning: applying config/samples failed (continuing)'

# Wait for keycloak and mailhog deployments to be ready (use helper)
if ! wait_for_deploy_by_label keycloak 120; then log 'Keycloak deployment not ready' ; exit 1; fi
if ! wait_for_deploy_by_label mailhog 120; then log 'Mailhog deployment not ready' ; exit 1; fi

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
[ -n "$KC_SVC_NAME" ] || { log "Keycloak service not found after wait"; exit 1; }

PF=$(start_port_forward "$KC_SVC_NS" "$KC_SVC_NAME" ${KEYCLOAK_FORWARD_PORT} ${KEYCLOAK_SVC_PORT})
JWKS_URL="https://breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local:${KEYCLOAK_FORWARD_PORT}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
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
[ "$code" = "200" ] || { log "JWKS timeout after 120 attempts (last status=$code)"; exit 1; }
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
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" run "$NETS_POD_NAME" --image=nicolaka/netshoot --restart=Always --command -- sleep infinity >/dev/null 2>&1 || true
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
  [ "$INST_CODE" = "200" ] || { log "Issuer not reachable in-cluster after 60 attempts (last=$INST_CODE)"; exit 1; }

  # Ensure apiserver can resolve the in-cluster Keycloak hostname when it runs with hostNetwork
  KC_CLUSTER_IP=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$KC_SVC_NS" get svc "$KC_SVC_NAME" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
  if [ -n "$KC_CLUSTER_IP" ] && [ "$KC_CLUSTER_IP" != "None" ]; then
    # Collect entries we want to ensure in control-plane /etc/hosts
    declare -a HOST_ENTRIES=()
    HOST_ENTRIES+=("$KC_CLUSTER_IP $KEYCLOAK_HOST")
    # Also map the webhook placeholder host (if it points to an in-cluster service) to the breakglass service IP when available
    BG_SVC_IP=$($KUBECTL get svc --all-namespaces -l app=breakglass -o jsonpath='{.items[0].spec.clusterIP}' 2>/dev/null || true)
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
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" run "$NETS_POD_NAME" --image=nicolaka/netshoot --restart=Always --command -- sleep infinity >/dev/null 2>&1 || true
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
  [ "$INST_CODE" = "200" ] || { log "Issuer not reachable in-cluster after 60 attempts (last=$INST_CODE)"; exit 1; }
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
    BG_SVC_IP=$($KUBECTL get svc --all-namespaces -l app=breakglass -o jsonpath='{.items[0].spec.clusterIP}' 2>/dev/null || true)
    if [ -n "$BG_SVC_IP" ] && [ "$BG_SVC_IP" != "None" ]; then
      HOST_ENTRIES+=("$BG_SVC_IP ${WEBHOOK_HOST_PLACEHOLDER}")
    fi
  else
    log "Could not determine Keycloak service ClusterIP (got: $KC_CLUSTER_IP); apiserver may still fail DNS"
  fi

  # Restart kube-apiserver to ensure OIDC authenticator re-initializes after Keycloak is reachable (discovery may have failed early)
  log 'Restarting kube-apiserver static pod to refresh OIDC discovery'
  docker exec ${CLUSTER_NAME}-control-plane sh -c 'touch /etc/kubernetes/manifests/kube-apiserver.yaml'
  sleep 5
  for i in {1..40}; do
  st=$(docker exec ${CLUSTER_NAME}-control-plane crictl ps --name kube-apiserver -o json 2>/dev/null | grep -c 'kube-apiserver');
    if [ "$st" -gt 0 ]; then
      # Optionally check apiserver healthz
      if kubectl get --raw='/readyz?verbose' >/dev/null 2>&1; then
        log "kube-apiserver restarted and ready (attempt $i)"
        break
      fi
    fi
    [ $(( i % 5 )) -eq 0 ] && log "Waiting for kube-apiserver restart (attempt $i)"
    sleep 2
  done

log 'Deploy controller and supporting resources via kustomize (config/dev)'
# create the system namespace and apply the development kustomize overlay
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create namespace system --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -

# Render and apply the dev overlay; this includes controller, rbac, mailhog, and other dev resources
KUBECONFIG="$HUB_KUBECONFIG" $KUSTOMIZE build config/dev | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -


# Render and apply cluster-config overrides used for single-cluster setup (substitute placeholders)
CLUSTER_ID_RENDER="${CLUSTER_CONFIG_ID}"
CLUSTER_CONFIGS_RENDERED_TMP="$TDIR/e2e-cluster-configs-rendered.yaml"
sed -e "s/CLUSTER_PLACEHOLDER_2/${CLUSTER_ID_RENDER}/g" \
  -e "s/CLUSTER_PLACEHOLDER/${CLUSTER_ID_RENDER}/g" \
  -e "s/TENANT_PLACEHOLDER/${TENANT_A}/g" \
  -e "s/TENANT_PLACEHOLDER_2/${TENANT_B}/g" \
  -e "s/SECRET_NAME_A/${TENANT_A}-admin/g" \
  -e "s/SECRET_NAME_B/${TENANT_B}-admin/g" \
  -e "s/CLUSTER_CONFIG_NAME_A/${TENANT_A}-config/g" \
  -e "s/CLUSTER_CONFIG_NAME_B/${TENANT_B}-config/g" \
  config/dev/resources/crs/cluster-configs-test.yaml > "$CLUSTER_CONFIGS_RENDERED_TMP" || true
ensure_no_placeholders "$CLUSTER_CONFIGS_RENDERED_TMP"
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f "$CLUSTER_CONFIGS_RENDERED_TMP" || true

DENY_POLICIES_RENDERED_TMP="$TDIR/e2e-deny-policies-rendered.yaml"
sed -e "s/CLUSTER_PLACEHOLDER/${CLUSTER_ID_RENDER}/g" \
  -e "s/TENANT_PLACEHOLDER/${TENANT_A}/g" \
  config/dev/resources/crs/deny-policies-test.yaml > "$DENY_POLICIES_RENDERED_TMP" || true
ensure_no_placeholders "$DENY_POLICIES_RENDERED_TMP"
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f "$DENY_POLICIES_RENDERED_TMP" || true

log 'Wait controller'
### Ensure controller uses the locally built image and wait for rollout by label
set_image_and_wait_by_label breakglass breakglass ${IMAGE} || { log 'Controller not ready'; exit 1; }

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
BG_SVC_NS=$($KUBECTL get svc --all-namespaces -l app=breakglass -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
BG_SVC_NAME=$($KUBECTL get svc --all-namespaces -l app=breakglass -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -n "$BG_SVC_NAME" ] && [ -n "$BG_SVC_NS" ]; then
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL patch svc "$BG_SVC_NAME" -n "$BG_SVC_NS" -p "{\"spec\":{\"type\":\"NodePort\",\"ports\":[{\"port\":8080,\"targetPort\":8080,\"nodePort\":${NODEPORT},\"protocol\":\"TCP\",\"name\":\"http\"}]}}" >/dev/null 2>&1 || true
else
  log 'Warning: breakglass service not found; skipping NodePort patch'
fi

log 'Create simulated tenant ClusterConfig referencing same cluster'
# The kind kubeconfig uses a loopback IP/ephemeral port (https://127.0.0.1:PORT) which is unreachable from pods.
# Rewrite the server endpoint to the in-cluster service DNS so the controller can reach the API.
MOD_KUBECONFIG="$TDIR/kind-setup-single-mod-kubeconfig.yaml"
cp "$HUB_KUBECONFIG" "$MOD_KUBECONFIG"

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

# Create tenant kubeconfig secrets using kubectl create --from-file to ensure valid base64
## Helpers: create secret and ClusterConfig for tenant
create_tenant() {
  local tenant="$1"
  local secret_name="${tenant}-admin"
  log "Creating kubeconfig secret for tenant: $tenant -> $secret_name"
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret generic "$secret_name" -n default --from-file=kubeconfig="$MOD_KUBECONFIG" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f - || true

  log "Applying ClusterConfig for tenant: $tenant"
  cat <<YAML | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f - || true
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${tenant}
spec:
  kubeconfigSecretRef:
    name: ${secret_name}
    namespace: default
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
cat <<YAML | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f - || true
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: breakglass-e2e-idp
spec:
  # Mark as primary so controller uses this as default provider
  primary: true
  oidc:
    # Authority URL pointing to test Keycloak instance (in-cluster DNS)
    authority: "https://breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local:8443/realms/${KEYCLOAK_REALM}"
    # OIDC client ID (must match realm configuration)
    clientID: "breakglass-ui"
    # Skip TLS verification for self-signed test certificates (NOT for production!)
    insecureSkipVerify: true
YAML

log 'Port-forward controller and keycloak for tests'
rm -f "$PF_FILE" || true
# Expose controller only (keycloak port-forward is already running from JWKS step)
# Use the discovered breakglass service name/namespace (BG_SVC_NAME/BG_SVC_NS) when available
if [ -n "${BG_SVC_NAME:-}" ] && [ -n "${BG_SVC_NS:-}" ]; then
  start_port_forward "$BG_SVC_NS" "$BG_SVC_NAME" ${CONTROLLER_FORWARD_PORT} 8081 >/dev/null 2>&1 || true
else
  start_port_forward "$DEV_NS" "breakglass" ${CONTROLLER_FORWARD_PORT} 8081 >/dev/null 2>&1 || true
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
[ "$c" = "200" ] || { log "Controller API timeout after 40 attempts (last status=$c)"; exit 1; }

# Verify server-side OIDC proxy by calling the proxied discovery endpoint
PROXY_OK=000
for i in {1..10}; do
  PROXY_URL="http://localhost:${CONTROLLER_FORWARD_PORT}/api/oidc/authority/.well-known/openid-configuration"
  PROXY_OK=$(curl -s -o /dev/null -w '%{http_code}' "${PROXY_URL}" || echo 000)
  printf '[single-e2e] OIDC proxy check attempt %d status=%s\n' "$i" "$PROXY_OK" >&2
  if [ "${PROXY_OK}" = "200" ]; then
    log "OIDC proxy discovery reachable"
    break
  fi
  sleep 1
done
if [ "${PROXY_OK}" != "200" ]; then
  log "Warning: OIDC proxy discovery did not return 200 (last=${PROXY_OK}); continuing but login flows may fail"
fi

log 'Deploy/verify MailHog for testing emails'
ensure_no_placeholders config/dev/resources/mailhog.yaml
MH_NS=$($KUBECTL get deploy --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
if [ -n "$MH_NS" ]; then
  log "MailHog already present in namespace $MH_NS; skipping apply"
else
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f config/dev/resources/mailhog.yaml
fi
for i in {1..60}; do
  MH_NS=$($KUBECTL get deploy --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
  MH_NAME=$($KUBECTL get deploy --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [ -n "$MH_NS" ] && [ -n "$MH_NAME" ]; then
    ready=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy/"$MH_NAME" -n "$MH_NS" -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo 0)
  else
    ready=0
  fi
  [ "$ready" = "1" ] && break
  sleep 2
done
[ "$ready" = "1" ] || { log 'MailHog not ready'; exit 1; }

log 'Port-forward MailHog UI'
# Discover mailhog service name (kustomize may add a namePrefix)
MH_SVC_NAME=$($KUBECTL get svc --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
MH_SVC_NS=$($KUBECTL get svc --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
if [ -n "$MH_SVC_NAME" ] && [ -n "$MH_SVC_NS" ]; then
  start_port_forward "$MH_SVC_NS" "$MH_SVC_NAME" ${MAILHOG_UI_PORT} 8025 >/dev/null 2>&1 || true
  log "MailHog UI available at http://localhost:${MAILHOG_UI_PORT} (svc: $MH_SVC_NAME ns: $MH_SVC_NS)"
else
  log 'MailHog service not found for port-forward; skipping'
fi

log 'Single-cluster setup complete'

# Generate a kubeconfig for an OIDC test user so host-side tests can authenticate
# Uses the local Keycloak port-forward which was started earlier (KEYCLOAK_FORWARD_PORT)
# Defaults match the users created in config/dev/resources/keycloak-realm.json
OIDC_TEST_USERNAME=${OIDC_TEST_USERNAME:-test-user}
OIDC_TEST_PASSWORD=${OIDC_TEST_PASSWORD:-test-password}
OIDC_CLIENT_ID=${OIDC_CLIENT_ID:-kubernetes}
OIDC_ISSUER="https://breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local:${KEYCLOAK_FORWARD_PORT}/realms/${KEYCLOAK_REALM}"
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
