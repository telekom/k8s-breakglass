#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Run the public reference stack against a clean kind cluster.  The script is
# deliberately self-contained: source mode builds only the selected image and
# both modes consume the published catalogue; bootstrap and identity fixtures
# are explicit inputs rather than hidden repository dependencies.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

MODE="${REFERENCE_MODE:-source}"
CLUSTER_NAME="${REFERENCE_CLUSTER_NAME:-breakglass-reference}"
CLUSTER_OWNED=false
NAMESPACE="${REFERENCE_NAMESPACE:-default}"
TENANT="${REFERENCE_TENANT:-tenant-a}"
IMAGE="${REFERENCE_IMAGE:-reference-breakglass:local}"

# These are public, immutable release inputs.  Override them only to test a
# newer public release; credentials are intentionally not accepted here.
AUTH_OPERATOR_VERSION="${AUTH_OPERATOR_VERSION:-v0.5.0-rc.2}"
BREAKGLASS_VERSION="${BREAKGLASS_VERSION:-v0.1.0-rc.7}"
CATALOGUE_VERSION="${CATALOGUE_VERSION:-0.2.0}" # charts/debug-session-catalogue contract
AUTH_OPERATOR_CHART="${AUTH_OPERATOR_CHART:-oci://ghcr.io/telekom/charts/auth-operator}"
PUBLISHED_IMAGE="${PUBLISHED_IMAGE:-ghcr.io/telekom/k8s-breakglass:${BREAKGLASS_VERSION}}"
CATALOGUE_CHART="${CATALOGUE_CHART:-oci://ghcr.io/telekom/k8s-breakglass/charts/debug-session-catalogue}"
CATALOGUE_CHART_DIGEST="${CATALOGUE_CHART_DIGEST:-}"
DEBUG_NAMESPACE="${REFERENCE_DEBUG_NAMESPACE:-reference-debug}"
CATALOGUE_RELEASE="${REFERENCE_CATALOGUE_RELEASE:-debug-catalogue}"
CATALOGUE_VALUES_FILE=""

# The bootstrap and token helper are optional contracts. A consumer can point
# the flow at its own disposable cluster bootstrap and identity fixture; the
# executable does not require this repository's e2e files to exist.
REFERENCE_SETUP_SCRIPT="${REFERENCE_SETUP_SCRIPT:-}"
REFERENCE_TOKEN_HELPER="${REFERENCE_TOKEN_HELPER:-}"
REFERENCE_ENV_FILE="${REFERENCE_ENV_FILE:-}"
REFERENCE_REQUESTER_GROUP="${REFERENCE_REQUESTER_GROUP:-reference-requesters}"
REFERENCE_ESCALATED_GROUP="${REFERENCE_ESCALATED_GROUP:-reference-restricted}"
REFERENCE_AUDIT_CONFIG_NAME="${REFERENCE_AUDIT_CONFIG_NAME:-reference-audit-config}"
REFERENCE_AUDIT_WEBHOOK_URL="${REFERENCE_AUDIT_WEBHOOK_URL:-}"

REQUESTER_USERNAME="${REFERENCE_REQUESTER_USERNAME:-reference-requester}"
REQUESTER_PASSWORD="${REFERENCE_REQUESTER_PASSWORD:-reference-requester-password}"
REQUESTER_EMAIL="${REFERENCE_REQUESTER_EMAIL:-reference-requester@example.com}"
APPROVER_USERNAME="${REFERENCE_APPROVER_USERNAME:-reference-approver}"
APPROVER_PASSWORD="${REFERENCE_APPROVER_PASSWORD:-reference-approver-password}"
APPROVER_EMAIL="${REFERENCE_APPROVER_EMAIL:-reference-approver@example.com}"
LABEL="reference-usage.example.com/run"
RUN_ELEVATED="${REFERENCE_RUN_ELEVATED:-false}"
VERIFY_SUPPLY_CHAIN="${REFERENCE_VERIFY_SUPPLY_CHAIN:-true}"
VERIFY_GH_ATTESTATION="${REFERENCE_VERIFY_GH_ATTESTATION:-false}"
PUBLISHED_IMAGE_DIGEST_REF=""
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reference-usage.XXXXXX")"

KUBECONFIG_FILE="${REFERENCE_KUBECONFIG:-${KUBECONFIG:-}}"
API_BASE=""
REQUESTER_TOKEN=""
APPROVER_TOKEN=""
SESSION_NAME=""
REJECTED_SESSION_NAME=""
DEBUG_SESSION_NAME=""
ELEVATED_DEBUG_SESSION_NAME=""
ESCALATION_NAME="reference-restricted-${RANDOM}"

die() { printf 'reference-usage: %s\n' "$*" >&2; exit 1; }
log() { printf 'reference-usage: %s\n' "$*"; }

require_commands() {
  local command
  for command in curl jq docker kind kubectl helm; do
    command -v "${command}" >/dev/null 2>&1 || die "required command not found: ${command}"
  done
}

validate_inputs() {
  local value name
  for name in NAMESPACE TENANT DEBUG_NAMESPACE CATALOGUE_RELEASE REFERENCE_REQUESTER_GROUP REFERENCE_ESCALATED_GROUP; do
    value="${!name}"
    if [[ ! "${value}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || (( ${#value} > 63 )); then
      die "${name} must be a DNS-safe Kubernetes name (max 63 characters)"
    fi
  done
  [[ "${RUN_ELEVATED}" == true || "${RUN_ELEVATED}" == false ]] || \
    die "REFERENCE_RUN_ELEVATED must be true or false"
  [[ "${VERIFY_GH_ATTESTATION}" == true || "${VERIFY_GH_ATTESTATION}" == false ]] || \
    die "REFERENCE_VERIFY_GH_ATTESTATION must be true or false"
  [[ "${APPROVER_EMAIL}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] || \
    die "REFERENCE_APPROVER_EMAIL must be a simple email address"
  [[ -n "${REFERENCE_AUDIT_WEBHOOK_URL}" ]] || \
    die "REFERENCE_AUDIT_WEBHOOK_URL is required for audit lifecycle verification"
  [[ "${REFERENCE_AUDIT_WEBHOOK_URL}" != *[[:space:][:cntrl:]]* ]] || \
    die "REFERENCE_AUDIT_WEBHOOK_URL must not contain whitespace or control characters"
}

cleanup() {
  set +e
  [[ -n "${CATALOGUE_VALUES_FILE}" ]] && rm -f "${CATALOGUE_VALUES_FILE}"
  [[ -d "${STATE_DIR}" ]] && rm -rf "${STATE_DIR}"
  if [[ -n "${KUBECONFIG_FILE}" ]]; then
    KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete auditconfig "${REFERENCE_AUDIT_CONFIG_NAME}" \
      --ignore-not-found >/dev/null 2>&1
    KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete breakglassescalation "${ESCALATION_NAME}" \
      -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1
    [[ -n "${SESSION_NAME}" ]] && KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete breakglasssession "${SESSION_NAME}" \
      -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1
    [[ -n "${REJECTED_SESSION_NAME}" ]] && KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete breakglasssession "${REJECTED_SESSION_NAME}" \
      -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1
    [[ -n "${DEBUG_SESSION_NAME}" ]] && KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete debugsession "${DEBUG_SESSION_NAME}" \
      -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1
    [[ -n "${ELEVATED_DEBUG_SESSION_NAME}" ]] && KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete debugsession "${ELEVATED_DEBUG_SESSION_NAME}" \
      -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1
  fi
  if [[ "${CLUSTER_OWNED}" == true ]] && command -v kind >/dev/null 2>&1; then
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

load_environment() {
  if [[ -n "${REFERENCE_ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${REFERENCE_ENV_FILE}"
  fi
  API_BASE="${REFERENCE_API_BASE:-${BREAKGLASS_API_URL:?BREAKGLASS_API_URL missing from reference environment}}"
  KUBECONFIG_FILE="${REFERENCE_KUBECONFIG:-${KUBECONFIG:?KUBECONFIG missing from reference environment}}"
  export KUBECONFIG="${KUBECONFIG_FILE}"
}

verify_public_artifacts() {
  [[ "${VERIFY_SUPPLY_CHAIN}" == true ]] || return 0
  [[ "${MODE}" == published ]] || return 0
  command -v cosign >/dev/null 2>&1 || die "cosign is required for published artifact verification"
  local identity="https://github.com/telekom/k8s-breakglass/.github/workflows/release.yml@refs/tags/v[0-9].*"
  [[ -n "${PUBLISHED_IMAGE_DIGEST_REF}" ]] || die "published image was not resolved to an immutable digest"
  log "Verifying keyless signature for ${PUBLISHED_IMAGE_DIGEST_REF}"
  cosign verify "${PUBLISHED_IMAGE_DIGEST_REF}" \
    --certificate-identity-regexp="${identity}" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" >/dev/null
  log "Verifying SPDX SBOM attestation"
  cosign verify-attestation "${PUBLISHED_IMAGE_DIGEST_REF}" --type spdxjson \
    --certificate-identity-regexp="${identity}" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" >/dev/null
  log "Verifying SLSA provenance attestation"
  cosign verify-attestation "${PUBLISHED_IMAGE_DIGEST_REF}" --type slsaprovenance \
    --certificate-identity-regexp="${identity}" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" >/dev/null
  if [[ "${VERIFY_GH_ATTESTATION}" == true ]]; then
    command -v gh >/dev/null 2>&1 || die "gh is required when REFERENCE_VERIFY_GH_ATTESTATION=true"
    gh attestation verify "${PUBLISHED_IMAGE_DIGEST_REF}" --repo telekom/k8s-breakglass >/dev/null
  fi

  [[ "${CATALOGUE_CHART_DIGEST}" =~ ^sha256:[a-f0-9]{64}$ ]] || \
    die "CATALOGUE_CHART_DIGEST must be a sha256 digest when published supply-chain verification is enabled"
  local chart_subject="${CATALOGUE_CHART#oci://}@${CATALOGUE_CHART_DIGEST}"
  log "Verifying keyless signature for ${chart_subject}"
  cosign verify "${chart_subject}" \
    --certificate-identity-regexp="${identity}" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" >/dev/null
  log "Verifying chart SPDX SBOM attestation"
  cosign verify-attestation "${chart_subject}" --type spdxjson \
    --certificate-identity-regexp="${identity}" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" >/dev/null
  log "Verifying chart SLSA provenance attestation"
  cosign verify-attestation "${chart_subject}" --type slsaprovenance \
    --certificate-identity-regexp="${identity}" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" >/dev/null
}

prepare_image() {
  if [[ "${MODE}" == source ]]; then
    log "Building source image ${IMAGE}"
    docker build --load --build-arg UI_FLAVOUR=oss -t "${IMAGE}" "${ROOT_DIR}"
  else
    log "Pulling public release image ${PUBLISHED_IMAGE}"
    docker pull "${PUBLISHED_IMAGE}"
    PUBLISHED_IMAGE_DIGEST_REF="$(docker image inspect "${PUBLISHED_IMAGE}" \
      --format '{{index .RepoDigests 0}}')"
    [[ "${PUBLISHED_IMAGE_DIGEST_REF}" == *@sha256:* ]] || \
      die "docker did not resolve ${PUBLISHED_IMAGE} to a registry digest"
    docker tag "${PUBLISHED_IMAGE}" "${IMAGE}"
  fi
}

install_stack() {
  log "Creating clean kind cluster ${CLUSTER_NAME}"
  if [[ -n "${REFERENCE_SETUP_SCRIPT}" ]]; then
    if ! kind get clusters 2>/dev/null | grep -Fxq "${CLUSTER_NAME}"; then
      CLUSTER_OWNED=true
    fi
    IMAGE="${IMAGE}" SKIP_BUILD=true CLUSTER_NAME="${CLUSTER_NAME}" \
      KIND_RETAIN_ON_FAILURE=false bash "${REFERENCE_SETUP_SCRIPT}"
  fi
  load_environment

  log "Installing public auth-operator chart ${AUTH_OPERATOR_VERSION}"
  helm upgrade --install auth-operator "${AUTH_OPERATOR_CHART}" \
    --version "${AUTH_OPERATOR_VERSION}" --namespace auth-operator-system \
    --create-namespace --wait --timeout 5m

  kubectl create namespace "${DEBUG_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
  log "Installing debug-session-catalogue ${CATALOGUE_VERSION}"
  CATALOGUE_VALUES_FILE="$(mktemp)"
  cat >"${CATALOGUE_VALUES_FILE}" <<YAML
requesters:
  groups: [${REFERENCE_REQUESTER_GROUP}]
  users: []
approvers:
  groups: []
  users: [${APPROVER_EMAIL}]
targets:
  clusters: [${TENANT}]
  clusterSelector: {}
targetNamespace: ${DEBUG_NAMESPACE}
fullnameOverride: ${CATALOGUE_RELEASE}
profiles:
  - name: workload-diagnostics
    intent: workload-diagnostics
    enabled: true
    elevated: false
    displayName: Workload diagnostics
    description: Consumer-defined restricted workload diagnostics profile.
    workloadType: Job
    replicas: 1
    imageKey: workload
    command: ["/usr/local/bin/workload-debug"]
    args: ["report"]
    requiredElevation: false
    preset: restricted
    capabilities: []
  - name: network-repair
    intent: network-repair
    enabled: ${RUN_ELEVATED}
    elevated: ${RUN_ELEVATED}
    displayName: Network repair (opt-in)
    description: Explicit elevated network repair profile.
    workloadType: Job
    replicas: 1
    imageKey: networkRepair
    command: ["/usr/local/bin/node-maintenance"]
    args: ["network-repair"]
    requiredElevation: true
    preset: elevated-node
    capabilities: [NET_ADMIN]
    allowExec: false
    extraDeployVariables:
      - name: targetNode
        displayName: Target node
        description: Exact Kubernetes node name to inspect and schedule onto.
        inputType: text
        required: true
      - name: interface
        displayName: Network interface
        description: Exact interface name on the target node.
        inputType: text
        required: true
      - name: action
        displayName: Repair action
        description: One allowlisted, reversible network repair action.
        inputType: select
        required: true
        options:
          - value: flush-neighbors
      - name: confirmation
        displayName: Confirmation
        description: Explicit confirmation for the selected operation.
        inputType: text
        required: true
    podOverridesTemplate: |
      nodeSelector:
        kubernetes.io/hostname: {{ .vars.targetNode | yamlQuote }}
      containers:
        - name: debug
          args:
            - network-repair
            - --target-node
            - {{ .vars.targetNode | yamlQuote }}
            - --interface
            - {{ .vars.interface | yamlQuote }}
            - --action
            - {{ .vars.action | yamlQuote }}
            - --evidence-dir
            - /evidence
            - --confirm
            - {{ .vars.confirmation | yamlQuote }}
    pod:
      volumeMounts:
        - name: evidence
          mountPath: /evidence
      volumes:
        - name: evidence
          emptyDir: {}
YAML
  local catalogue_source="${CATALOGUE_CHART}"
  local -a chart_args=(upgrade --install "${CATALOGUE_RELEASE}" "${catalogue_source}" \
    --namespace "${DEBUG_NAMESPACE}" --values "${CATALOGUE_VALUES_FILE}" --wait --timeout 5m)
  if [[ "${MODE}" == published && "${VERIFY_SUPPLY_CHAIN}" == true ]]; then
    chart_args[3]="${CATALOGUE_CHART}@${CATALOGUE_CHART_DIGEST}"
  else
    chart_args+=(--version "${CATALOGUE_VERSION}")
  fi
  helm "${chart_args[@]}"
  kubectl get debugsessiontemplate -l "app.kubernetes.io/name=debug-session-catalogue" >/dev/null
  for resource in debugsessiontemplate debugpodtemplate; do
    kubectl get "${resource}/${CATALOGUE_RELEASE}-workload-diagnostics" >/dev/null || \
      die "catalogue did not render the consumer-defined workload-diagnostics profile (${resource})"
  done
}

configure_reference() {
  # Reference-specific resources carry a label so the test can prove cleanup
  # without deleting catalogue-owned resources.
  local audit_url_json
  audit_url_json="$(printf '%s' "${REFERENCE_AUDIT_WEBHOOK_URL}" | jq -Rr @json)"
  kubectl apply -f - <<YAML
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: reference-restricted-role
  labels:
    ${LABEL}: "true"
spec:
  targetRole: ClusterRole
  targetName: reference-restricted-role
  scopeNamespaced: false
  restrictedResources:
    - name: secrets
      singularName: secret
      namespaced: true
      group: ""
      kind: Secret
      verbs: ["*"]
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: reference-requester
  labels:
    ${LABEL}: "true"
spec:
  targetName: reference-requester
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: Group
      name: ${REFERENCE_REQUESTER_GROUP}
  clusterRoleBindings:
    clusterRoleRefs: [reference-restricted-role]
YAML
  for _ in $(seq 1 60); do
    kubectl get clusterrole reference-restricted-role >/dev/null 2>&1 && break
    sleep 2
  done
  kubectl get clusterrole reference-restricted-role >/dev/null || die "auth-operator did not generate reference-restricted-role"
  kubectl apply -f - <<YAML
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: AuditConfig
metadata:
  name: ${REFERENCE_AUDIT_CONFIG_NAME}
spec:
  enabled: true
  sinks:
    - name: reference-webhook
      type: webhook
      webhook:
        url: ${audit_url_json}
        headers:
          Content-Type: application/json
        timeoutSeconds: 10
YAML
  kubectl apply -f - <<YAML
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: ${ESCALATION_NAME}
  namespace: ${NAMESPACE}
  labels:
    ${LABEL}: "true"
spec:
  allowed:
    clusters: [${TENANT}]
    groups: [${REFERENCE_REQUESTER_GROUP}]
  escalatedGroup: ${REFERENCE_ESCALATED_GROUP}
  maxValidFor: 10m
  approvalTimeout: 5m
  blockSelfApproval: true
  approvers:
    users: [${APPROVER_EMAIL}]
  requestReason:
    mandatory: true
    description: "Reference test reason"
YAML
  kubectl wait --for=condition=Ready "breakglassescalation/${ESCALATION_NAME}" \
    -n "${NAMESPACE}" --timeout=120s
}

api_request() {
  local token="$1" method="$2" path="$3" payload="${4:-}" response status
  local auth_header="${STATE_DIR}/authorization.header"
  printf 'Authorization: Bearer %s\n' "${token}" > "${auth_header}"
  chmod 600 "${auth_header}"
  local -a args=(-sS -o "${STATE_DIR}/response.json" -w '%{http_code}' -X "${method}" \
    -H 'Accept: application/json' -H 'Content-Type: application/json' --header "@${auth_header}")
  [[ -n "${payload}" ]] && args+=(--data "${payload}")
  status="$(curl "${args[@]}" "${API_BASE}${path}")"
  response="$(< "${STATE_DIR}/response.json")"
  printf '%s\n' "${status}" > "${STATE_DIR}/status"
  printf '%s' "${response}" > "${STATE_DIR}/body"
}

expect_status() {
  local expected="$1" actual
  actual="$(< "${STATE_DIR}/status")"
  [[ "${actual}" == "${expected}" ]] || die "expected HTTP ${expected}, got ${actual}: $(< "${STATE_DIR}/body")"
}

wait_for_state() {
  local token="$1" name="$2" expected="$3" state=''
  for _ in $(seq 1 90); do
    api_request "${token}" GET "/api/breakglassSessions/${name}?namespace=${NAMESPACE}"
    if [[ "$(< "${STATE_DIR}/status")" == 200 ]]; then
      state="$(jq -r '.status.state // .session.status.state // empty' "${STATE_DIR}/body")"
      [[ "${state}" == "${expected}" ]] && return 0
    fi
    sleep 1
  done
  die "timed out waiting for ${name} to reach ${expected} (last state: ${state})"
}

webhook_check() {
  local expected="$1" resource="$2" payload response allowed
  payload="$(jq -n --arg user "${REQUESTER_EMAIL}" --arg base_group "${REFERENCE_REQUESTER_GROUP}" --arg escalated_group "${REFERENCE_ESCALATED_GROUP}" --arg resource "${resource}" --arg namespace "${NAMESPACE}" '{apiVersion:"authorization.k8s.io/v1",kind:"SubjectAccessReview",spec:{user:$user,groups:[$base_group,$escalated_group],resourceAttributes:{verb:"get",resource:$resource,namespace:$namespace}}}')"
  response="$(curl -sS -X POST -H 'Content-Type: application/json' --data "${payload}" "${API_BASE}/api/breakglass/webhook/authorize/${TENANT}")"
  allowed="$(jq -r '.status.allowed' <<<"${response}")"
  [[ "${allowed}" == "${expected}" ]] || die "webhook ${resource}: expected allowed=${expected}, got ${response}"
}

reference_flow() {
  [[ -n "${REFERENCE_TOKEN_HELPER}" ]] || die "REFERENCE_TOKEN_HELPER is required for the selected identity fixture"
  local issuer_host="${KEYCLOAK_ISSUER_HOST:-}"
  [[ -n "${issuer_host}" ]] || die "KEYCLOAK_ISSUER_HOST is required from the selected reference environment"
  REQUESTER_TOKEN="$(HOST_HEADER="${issuer_host}" PORT="${KEYCLOAK_PORT:-8443}" \
    "${REFERENCE_TOKEN_HELPER}" "${REQUESTER_USERNAME}" "${REQUESTER_PASSWORD}")"
  APPROVER_TOKEN="$(HOST_HEADER="${issuer_host}" PORT="${KEYCLOAK_PORT:-8443}" \
    "${REFERENCE_TOKEN_HELPER}" "${APPROVER_USERNAME}" "${APPROVER_PASSWORD}")"

  log "Checking restricted access is denied before approval"
  webhook_check false configmaps

  local payload
  payload="$(jq -n --arg cluster "${TENANT}" --arg user "${REQUESTER_EMAIL}" --arg group "${REFERENCE_ESCALATED_GROUP}" '{cluster:$cluster,user:$user,group:$group,reason:"reference-usage restricted session"}')"
  api_request "${REQUESTER_TOKEN}" POST /api/breakglassSessions "${payload}"
  expect_status 201
  SESSION_NAME="$(jq -er '.metadata.name' "${STATE_DIR}/body")"

  log "Checking requester cannot self-approve"
  api_request "${REQUESTER_TOKEN}" POST "/api/breakglassSessions/${SESSION_NAME}/approve?namespace=${NAMESPACE}" '{"reason":"self approval must be denied"}'
  expect_status 403

  log "Approving with the distinct approver identity"
  api_request "${APPROVER_TOKEN}" POST "/api/breakglassSessions/${SESSION_NAME}/approve?namespace=${NAMESPACE}" '{"reason":"reference approval"}'
  expect_status 200
  wait_for_state "${REQUESTER_TOKEN}" "${SESSION_NAME}" Approved
  webhook_check true configmaps

  log "Checking a second request can be explicitly rejected"
  api_request "${REQUESTER_TOKEN}" POST /api/breakglassSessions "${payload}"
  expect_status 201
  REJECTED_SESSION_NAME="$(jq -er '.metadata.name' "${STATE_DIR}/body")"
  api_request "${APPROVER_TOKEN}" POST "/api/breakglassSessions/${REJECTED_SESSION_NAME}/reject?namespace=${NAMESPACE}" '{"reason":"reference denial"}'
  expect_status 200
  wait_for_state "${REQUESTER_TOKEN}" "${REJECTED_SESSION_NAME}" Rejected

  log "Terminating the approved session"
  api_request "${REQUESTER_TOKEN}" POST "/api/breakglassSessions/${SESSION_NAME}/drop?namespace=${NAMESPACE}"
  expect_status 200
  wait_for_state "${REQUESTER_TOKEN}" "${SESSION_NAME}" Expired

  log "Checking audit recording contains the reference session"
  local audit_url="${AUDIT_WEBHOOK_RECEIVER_EXTERNAL_URL:-http://localhost:${AUDIT_WEBHOOK_RECEIVER_PORT:-18080}}/events"
  local audit=''
  for _ in $(seq 1 30); do
    audit="$(curl -fsS "${audit_url}" 2>/dev/null || true)"
    if grep -Fq "${SESSION_NAME}" <<<"${audit}" && grep -Fq "${REJECTED_SESSION_NAME}" <<<"${audit}"; then break; fi
    sleep 1
  done
  grep -Fq "${SESSION_NAME}" <<<"${audit}" || die "audit recording did not contain ${SESSION_NAME}"
  grep -Fq "${REJECTED_SESSION_NAME}" <<<"${audit}" || die "audit recording did not contain ${REJECTED_SESSION_NAME}"
  for event_type in session.requested session.approved session.denied session.dropped; do
    grep -Fq "${event_type}" <<<"${audit}" || die "audit recording did not contain ${event_type}"
  done
}

wait_for_debug_state() {
  local token="$1" name="$2" expected="$3" state=''
  for _ in $(seq 1 120); do
    api_request "${token}" GET "/api/debugSessions/${name}"
    if [[ "$(< "${STATE_DIR}/status")" == 200 ]]; then
      state="$(jq -r '.status.state // empty' "${STATE_DIR}/body")"
      [[ "${state}" == "${expected}" ]] && return 0
      [[ "${state}" == Failed ]] && die "debug session ${name} failed: $(< "${STATE_DIR}/body")"
    fi
    sleep 1
  done
  die "timed out waiting for debug session ${name} to reach ${expected} (last state: ${state})"
}

wait_for_debug_pod() {
  local name="$1" pod='' phase=''
  for _ in $(seq 1 120); do
    pod="$(kubectl get pods -n "${DEBUG_NAMESPACE}" -l "breakglass.t-caas.telekom.com/session=${name}" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [[ -n "${pod}" ]]; then
      phase="$(kubectl get pod "${pod}" -n "${DEBUG_NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
      case "${phase}" in
        Running|Succeeded)
          printf '%s' "${pod}"
          return 0
          ;;
        Failed)
          die "debug workload for ${name} failed: $(kubectl logs -n "${DEBUG_NAMESPACE}" "${pod}" 2>&1 || true)"
          ;;
      esac
    fi
    sleep 1
  done
  die "timed out waiting for debug workload for ${name}"
}

assert_debug_audit() {
  local name="$1" audit_url="${AUDIT_WEBHOOK_RECEIVER_EXTERNAL_URL:-http://localhost:${AUDIT_WEBHOOK_RECEIVER_PORT:-18080}}/events" audit=''
  for _ in $(seq 1 45); do
    audit="$(curl -fsS "${audit_url}" 2>/dev/null || true)"
    if grep -Fq "${name}" <<<"${audit}" && grep -Fq 'debug_session.created' <<<"${audit}" && \
      grep -Fq 'debug_session.started' <<<"${audit}" && grep -Fq 'debug_session.resource_deployed' <<<"${audit}" && \
      grep -Fq 'debug_session.terminated' <<<"${audit}" && \
      grep -Fq 'debug_session.resource_cleanup' <<<"${audit}"; then
      return 0
    fi
    sleep 1
  done
  die "audit recording did not contain the complete debug lifecycle for ${name}: ${audit}"
}

run_debug_session() {
  local template="$1" elevated="$2" payload pod command_output node interface
  payload="$(jq -n --arg template "${template}" --arg cluster "${TENANT}" --arg ns "${DEBUG_NAMESPACE}" \
    '{templateRef:$template,cluster:$cluster,targetNamespace:$ns,requestedDuration:"10m",reason:"reference debug diagnostics command"}')"
  if [[ "${elevated}" == true ]]; then
    node="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')"
    interface="${REFERENCE_NODE_INTERFACE:-lo}"
    payload="$(jq -n --arg template "${template}" --arg cluster "${TENANT}" --arg ns "${DEBUG_NAMESPACE}" \
      --arg node "${node}" --arg interface "${interface}" \
      '{templateRef:$template,cluster:$cluster,targetNamespace:$ns,requestedDuration:"10m",reason:"reference debug diagnostics command",extraDeployValues:{targetNode:$node,interface:$interface,action:"flush-neighbors",confirmation:"NETWORK-REPAIR"}}')"
  fi
  api_request "${REQUESTER_TOKEN}" POST /api/debugSessions "${payload}"
  expect_status 201
  if [[ "${elevated}" == true ]]; then
    ELEVATED_DEBUG_SESSION_NAME="$(jq -er '.metadata.name' "${STATE_DIR}/body")"
    local name="${ELEVATED_DEBUG_SESSION_NAME}"
  else
    DEBUG_SESSION_NAME="$(jq -er '.metadata.name' "${STATE_DIR}/body")"
    local name="${DEBUG_SESSION_NAME}"
  fi

  api_request "${REQUESTER_TOKEN}" POST "/api/debugSessions/${name}/approve" '{"reason":"requester self-approval must be denied"}'
  expect_status 403
  api_request "${APPROVER_TOKEN}" POST "/api/debugSessions/${name}/approve" '{"reason":"reference debug approval"}'
  expect_status 200
  wait_for_debug_state "${REQUESTER_TOKEN}" "${name}" Active
  pod="$(wait_for_debug_pod "${name}")"

  command_output="$(kubectl logs -n "${DEBUG_NAMESPACE}" "${pod}")"
  if [[ "${elevated}" == true ]]; then
    grep -Fq 'Repair completed' <<<"${command_output}" || \
      die "network-repair command did not complete successfully: ${command_output}"
    kubectl get debugsession "${name}" -n "${NAMESPACE}" \
      -o jsonpath='{.status.allowedPodOperations.exec}' | grep -q false || \
      die "node-oriented catalogue session unexpectedly allows exec"
  else
    grep -Fq '=== workload-debug report ===' <<<"${command_output}" || \
      die "workload-debug command did not produce its report: ${command_output}"
  fi

  api_request "${REQUESTER_TOKEN}" POST "/api/debugSessions/${name}/terminate"
  expect_status 200
  wait_for_debug_state "${REQUESTER_TOKEN}" "${name}" Terminated
  for _ in $(seq 1 60); do
    if ! kubectl get pods -n "${DEBUG_NAMESPACE}" -l "breakglass.t-caas.telekom.com/session=${name}" \
      -o name 2>/dev/null | grep -q .; then
      break
    fi
    sleep 1
  done
  kubectl get pods -n "${DEBUG_NAMESPACE}" -l "breakglass.t-caas.telekom.com/session=${name}" \
    -o name 2>/dev/null | grep -q . && die "debug workload remains after ${name} termination"
  assert_debug_audit "${name}"
}

debug_session_flow() {
  log "Running restricted DebugSession request, approval, command, audit, and cleanup"
  run_debug_session "${CATALOGUE_RELEASE}-workload-diagnostics" false
  [[ "${RUN_ELEVATED}" == true ]] || { log "Elevated DebugSession disabled (set REFERENCE_RUN_ELEVATED=true to opt in)"; return; }
  log "Running explicitly elevated DebugSession opt-in"
  run_debug_session "${CATALOGUE_RELEASE}-network-repair" true
}

assert_zero_residual() {
  kubectl delete auditconfig "${REFERENCE_AUDIT_CONFIG_NAME}" --ignore-not-found >/dev/null
  kubectl delete roledefinition,binddefinition -A -l "${LABEL}=true" --ignore-not-found --wait >/dev/null
  for session in "${SESSION_NAME}" "${REJECTED_SESSION_NAME}"; do
    [[ -n "${session}" ]] && kubectl delete breakglasssession "${session}" -n "${NAMESPACE}" \
      --ignore-not-found --wait >/dev/null
  done
  kubectl delete breakglassescalation -A -l "${LABEL}=true" --ignore-not-found --wait >/dev/null
  [[ -n "${DEBUG_SESSION_NAME}" ]] && kubectl delete debugsession "${DEBUG_SESSION_NAME}" -n "${NAMESPACE}" --ignore-not-found --wait >/dev/null
  [[ -n "${ELEVATED_DEBUG_SESSION_NAME}" ]] && kubectl delete debugsession "${ELEVATED_DEBUG_SESSION_NAME}" -n "${NAMESPACE}" --ignore-not-found --wait >/dev/null
  for session in "${SESSION_NAME}" "${REJECTED_SESSION_NAME}"; do
    if [[ -n "${session}" ]] && kubectl get breakglasssession "${session}" -n "${NAMESPACE}" \
      -o name 2>/dev/null | grep -q .; then
      die "reference session ${session} remains"
    fi
  done
  kubectl get breakglassescalation -A -l "${LABEL}=true" -o name | grep -q . && die "reference escalations remain"
  kubectl get roledefinition,binddefinition -A -l "${LABEL}=true" -o name | grep -q . && die "auth-operator reference objects remain"
  kubectl wait --for=delete clusterrole/reference-restricted-role --timeout=60s >/dev/null 2>&1 || \
    die "generated reference role remains"
  for session in "${DEBUG_SESSION_NAME}" "${ELEVATED_DEBUG_SESSION_NAME}"; do
    if [[ -n "${session}" ]] && kubectl get debugsession "${session}" -n "${NAMESPACE}" \
      -o name 2>/dev/null | grep -q .; then
      die "debug session ${session} remains"
    fi
  done
  kubectl get deployment,daemonset,job,pod,role,rolebinding,networkpolicy -n "${DEBUG_NAMESPACE}" \
    -l "breakglass.t-caas.telekom.com/session" -o name 2>/dev/null | grep -q . && die "debug workload or policy resources remain"
  kubectl get clusterrole,clusterrolebinding -l "breakglass.t-caas.telekom.com/session" \
    -o name 2>/dev/null | grep -q . && die "debug cluster policy resources remain"
  kubectl delete namespace "${DEBUG_NAMESPACE}" --ignore-not-found --wait >/dev/null
  log "Reference resources have zero residual objects"
}

main() {
  [[ "${MODE}" == source || "${MODE}" == published ]] || die "REFERENCE_MODE must be source or published"
  validate_inputs
  require_commands
  prepare_image
  verify_public_artifacts
  install_stack
  configure_reference
  reference_flow
  debug_session_flow
  assert_zero_residual
  log "Reference usage passed (${MODE} mode)"
}

main "$@"
