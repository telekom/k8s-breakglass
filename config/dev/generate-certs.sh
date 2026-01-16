#!/usr/bin/env bash
set -euo pipefail
# Single-cluster variant: Keycloak + Breakglass controller + webhook auth all in one kind cluster.
# Replaces previous hub+tenant topology by creating only one cluster and using a ClusterConfig
# that points back to the same cluster (simulated tenant "tenant-a").

# --- Tools (can be overridden by env) ---
KUBECTL=${KUBECTL:-kubectl}
KUSTOMIZE=${KUSTOMIZE:-bin/kustomize}

# --- TLS / temp directories (kept as before, but configurable) ---
TDIR=${TDIR:-}
TLS_DIR=${TLS_DIR:-}

# --- Keycloak ---
KEYCLOAK_HOST=${KEYCLOAK_HOST:-breakglass-keycloak.breakglass-system.svc.cluster.local}
CONTROLLER_FORWARD_PORT=${CONTROLLER_FORWARD_PORT:-28081} # local port forwarded to controller svc:8080


REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TDIR=${TDIR:-"$REPO_ROOT/dev/certs/kind-setup-single-tdir"}
mkdir -p "$TDIR"
KEYCLOAK_CA_FILE="$TDIR/keycloak-ca.crt"

TLS_DIR=${TLS_DIR:-"$REPO_ROOT/dev/certs/kind-setup-single-tls"}
mkdir -p "$TLS_DIR"
OPENSSL_CONF_KEYCLOAK="$TLS_DIR/req.cnf"

# Default HUB_KUBECONFIG to repo-local files (can be overridden)
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
