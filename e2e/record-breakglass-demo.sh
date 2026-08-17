#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_ENV_FILE="${ROOT_DIR}/e2e/kind-setup-single-tdir/e2e-env.sh"
PLAY_SCRIPT="${ROOT_DIR}/e2e/record-breakglass-demo.sh"
RECORDING_FILE="${BREAKGLASS_DEMO_RECORDING:-${ROOT_DIR}/docs/demos/breakglass-api-flow.cast}"

KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-breakglass-hub}"
CLUSTER_NAME="${BREAKGLASS_DEMO_CLUSTER:-tenant-a}"
NAMESPACE=default
DEMO_ESCALATED_GROUP=complete-flow-test-admins
DEMO_ID="${BREAKGLASS_DEMO_ID:-$(date -u +%Y%m%d%H%M%S)}"
DEMO_ESCALATION_NAME="${DEMO_ESCALATION_NAME:-${BREAKGLASS_DEMO_ESCALATION_NAME:-copilot-demo-${DEMO_ID}}}"

REQUESTER_USERNAME=complete-flow-requester
REQUESTER_PASSWORD=complete-flow-requester-password
REQUESTER_EMAIL=complete-flow-requester@example.com
APPROVER_USERNAME=complete-flow-approver
APPROVER_PASSWORD=complete-flow-approver-password
APPROVER_EMAIL=complete-flow-approver@example.com
DEBUG_USERNAME=test-user
DEBUG_PASSWORD=test-password
DEMO_PAUSE="${BREAKGLASS_DEMO_PAUSE:-2}"

API_BASE=
WEBHOOK_BASE=
TMP_DIR=
RESPONSE_FILE=
REQUESTER_TOKEN=
APPROVER_TOKEN=
DEBUG_TOKEN=
SESSION_NAME=
DEBUG_SESSION_NAME=

die() {
  printf 'demo: %s\n' "$*" >&2
  exit 1
}

step() {
  printf '\n%s\n' "$1"
  printf 'What this proves: %s\n' "$2"
  sleep "$DEMO_PAUSE"
}

load_e2e_environment() {
  local original_kubeconfig="${KUBECONFIG-__breakglass_demo_unset__}"

  if [[ -f "$E2E_ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$E2E_ENV_FILE"
  fi
  if [[ "$original_kubeconfig" == "__breakglass_demo_unset__" ]]; then
    unset KUBECONFIG
  else
    export KUBECONFIG="$original_kubeconfig"
  fi
  if [[ -n "${KUBECONFIG:-}" ]] &&
    ! kubectl --kubeconfig "$KUBECONFIG" config get-contexts "$KUBECTL_CONTEXT" >/dev/null 2>&1; then
    unset KUBECONFIG
  fi

  API_BASE="${BREAKGLASS_API_URL:-http://localhost:8080}"
  API_BASE="${API_BASE%/}"
  WEBHOOK_BASE="${BREAKGLASS_WEBHOOK_URL:-$API_BASE}"
  WEBHOOK_BASE="${WEBHOOK_BASE%/}"
  : "${KEYCLOAK_HOST:=https://localhost:8443}"
  : "${KEYCLOAK_ISSUER_HOST:=breakglass-keycloak.breakglass-system.svc.cluster.local:8443}"
}

require_commands() {
  local command
  for command in curl jq kubectl; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
  done
}

check_services() {
  curl -fsS "${API_BASE}/api/config" >/dev/null ||
    die "Breakglass API is not reachable at ${API_BASE}; start the E2E port-forwards first"
  curl -kfsS "${KEYCLOAK_HOST}" >/dev/null ||
    die "Keycloak is not reachable at ${KEYCLOAK_HOST}; start the E2E port-forwards first"
}

get_token() {
  HOST_HEADER="$KEYCLOAK_ISSUER_HOST" \
    PORT="${KEYCLOAK_PORT:-8443}" \
    "$ROOT_DIR/e2e/get-token.sh" "$1" "$2"
}

apply_demo_escalation() {
  kubectl --context "$KUBECTL_CONTEXT" apply -f - >/dev/null <<EOF
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: ${DEMO_ESCALATION_NAME}
  namespace: ${NAMESPACE}
  labels:
    breakglass.dev/demo: "true"
spec:
  escalatedGroup: ${DEMO_ESCALATED_GROUP}
  maxValidFor: "30m"
  approvalTimeout: "15m"
  allowed:
    clusters:
      - ${CLUSTER_NAME}
    groups:
      - complete-flow-requester-base
  approvers:
    users:
      - ${APPROVER_EMAIL}
  requestReason:
    mandatory: true
    description: "Incident reference and justification"
EOF

  kubectl --context "$KUBECTL_CONTEXT" wait \
    --for=condition=Ready \
    "breakglassescalation/${DEMO_ESCALATION_NAME}" \
    --namespace "$NAMESPACE" \
    --timeout=90s >/dev/null
}

cleanup_escalation() {
  kubectl --context "$KUBECTL_CONTEXT" delete \
    "breakglassescalation/${DEMO_ESCALATION_NAME}" \
    --namespace "$NAMESPACE" \
    --ignore-not-found \
    --wait=true >/dev/null 2>&1 || true
}

api_request() {
  local token="$1"
  local method="$2"
  local path="$3"
  local data="${4:-}"
  local -a args=(
    -sS
    -o "$RESPONSE_FILE"
    -w "%{http_code}"
    -X "$method"
    -H "Accept: application/json"
    -H "Content-Type: application/json"
    -H "Authorization: Bearer ${token}"
  )

  if [[ -n "$data" ]]; then
    args+=(--data "$data")
  fi

  LAST_STATUS="$(curl "${args[@]}" "${API_BASE}${path}")"
  LAST_BODY="$(cat "$RESPONSE_FILE")"
}

webhook_request() {
  local verb="$1"
  local resource="$2"
  local payload

  payload="$(jq -n \
    --arg user "$REQUESTER_EMAIL" \
    --arg base_group "complete-flow-requester-base" \
    --arg escalated_group "$DEMO_ESCALATED_GROUP" \
    --arg verb "$verb" \
    --arg resource "$resource" \
    '{
      apiVersion: "authorization.k8s.io/v1",
      kind: "SubjectAccessReview",
      spec: {
        user: $user,
        groups: [$base_group, $escalated_group],
        resourceAttributes: {
          verb: $verb,
          group: "",
          resource: $resource,
          namespace: "default"
        }
      }
    }')"

  LAST_STATUS="$(curl -sS \
    -o "$RESPONSE_FILE" \
    -w "%{http_code}" \
    -X POST \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    --data "$payload" \
    "${WEBHOOK_BASE}/api/breakglass/webhook/authorize/${CLUSTER_NAME}")"
  LAST_BODY="$(cat "$RESPONSE_FILE")"
}

expect_status() {
  if [[ "$LAST_STATUS" != "$1" ]]; then
    printf 'Unexpected HTTP status %s (expected %s):\n%s\n' \
      "$LAST_STATUS" "$1" "$LAST_BODY" >&2
    exit 1
  fi
}

cleanup_play() {
  if [[ -n "$DEBUG_SESSION_NAME" && -n "$DEBUG_TOKEN" ]]; then
    curl -sS -o /dev/null -X POST \
      -H "Authorization: Bearer ${DEBUG_TOKEN}" \
      "${API_BASE}/api/debugSessions/${DEBUG_SESSION_NAME}/terminate" \
      >/dev/null 2>&1 || true
  fi

  if [[ -n "$SESSION_NAME" && -n "$REQUESTER_TOKEN" ]]; then
    curl -sS -o /dev/null -X POST \
      -H "Authorization: Bearer ${REQUESTER_TOKEN}" \
      "${API_BASE}/api/breakglassSessions/${SESSION_NAME}/drop?namespace=${NAMESPACE}" \
      >/dev/null 2>&1 || true
  fi

  if [[ -n "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}

wait_for_breakglass_state() {
  local expected="$1"
  local state

  for _ in $(seq 1 60); do
    api_request "$REQUESTER_TOKEN" GET \
      "/api/breakglassSessions/${SESSION_NAME}?namespace=${NAMESPACE}"
    if [[ "$LAST_STATUS" == "200" ]]; then
      state="$(jq -r '.status.state // .session.status.state // empty' <<<"$LAST_BODY")"
      if [[ "$state" == "$expected" ]]; then
        return
      fi
    fi
    sleep 1
  done

  printf 'Timed out waiting for BreakglassSession %s to become %s:\n%s\n' \
    "$SESSION_NAME" "$expected" "$LAST_BODY" >&2
  exit 1
}

wait_for_debug_state() {
  local expected="$1"
  local state

  for _ in $(seq 1 90); do
    api_request "$DEBUG_TOKEN" GET "/api/debugSessions/${DEBUG_SESSION_NAME}"
    if [[ "$LAST_STATUS" == "200" ]]; then
      state="$(jq -r '.status.state // empty' <<<"$LAST_BODY")"
      if [[ "$state" == "$expected" ]]; then
        return
      fi
      if [[ "$state" == "Failed" ]]; then
        printf 'DebugSession failed:\n%s\n' "$LAST_BODY" >&2
        exit 1
      fi
    fi
    sleep 2
  done

  printf 'Timed out waiting for DebugSession %s to become %s:\n%s\n' \
    "$DEBUG_SESSION_NAME" "$expected" "$LAST_BODY" >&2
  exit 1
}

run_demo() {
  load_e2e_environment
  require_commands
  check_services

  TMP_DIR="$(mktemp -d)"
  RESPONSE_FILE="${TMP_DIR}/response.json"
  trap cleanup_play EXIT

  REQUESTER_TOKEN="$(get_token "$REQUESTER_USERNAME" "$REQUESTER_PASSWORD")"
  APPROVER_TOKEN="$(get_token "$APPROVER_USERNAME" "$APPROVER_PASSWORD")"
  DEBUG_TOKEN="$(get_token "$DEBUG_USERNAME" "$DEBUG_PASSWORD")"

  printf '%s\n' 'Breakglass user journey'
  printf '%s\n' 'E2E cluster: tenant-a | API: http://localhost:8080'
  printf '%s\n' 'Credentials are held in memory and are not printed.'
  sleep "$DEMO_PAUSE"

  step \
    '1. A protected request is denied before approval' \
    'The authorization webhook fails closed until the requester has an approved session.'
  printf '%s\n' '$ POST /api/breakglass/webhook/authorize/tenant-a (get configmaps)'
  webhook_request get configmaps
  expect_status 200
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq '{allowed: .status.allowed, reason: .status.reason}' <<<"$LAST_BODY"
  printf '%s\n' 'Before state: no approved session -> webhook denied the request.'
  sleep "$DEMO_PAUSE"

  step \
    '2. The requester discovers an available escalation' \
    'The REST API lists only ready escalations matching the requester and target cluster.'
  printf '%s\n' '$ GET /api/breakglassEscalations?activeOnly=true&cluster=tenant-a'
  api_request "$REQUESTER_TOKEN" GET \
    "/api/breakglassEscalations?activeOnly=true&cluster=${CLUSTER_NAME}"
  expect_status 200
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq --arg name "$DEMO_ESCALATION_NAME" \
    '{total, items: [.items[] | select(.metadata.name == $name) | {
      name: .metadata.name,
      escalatedGroup: .spec.escalatedGroup,
      maxValidFor: .spec.maxValidFor,
      approvalTimeout: .spec.approvalTimeout
    }]}' <<<"$LAST_BODY"
  sleep "$DEMO_PAUSE"

  step \
    '3. The requester creates a temporary access request' \
    'The API records the target, requested group, incident reason, and pending state.'
  printf '%s\n' '$ POST /api/breakglassSessions'
  session_payload="$(jq -n \
    --arg cluster "$CLUSTER_NAME" \
    --arg user "$REQUESTER_EMAIL" \
    --arg group "$DEMO_ESCALATED_GROUP" \
    '{
      cluster: $cluster,
      user: $user,
      group: $group,
      reason: "INC-DEMO-001: inspect the service configuration"
    }')"
  api_request "$REQUESTER_TOKEN" POST /api/breakglassSessions "$session_payload"
  expect_status 201
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq '{name: .metadata.name, namespace: .metadata.namespace, state: .status.state}' \
    <<<"$LAST_BODY"
  SESSION_NAME="$(jq -er '.metadata.name' <<<"$LAST_BODY")"
  wait_for_breakglass_state Pending
  sleep "$DEMO_PAUSE"

  step \
    '4. An authorized approver approves the request' \
    'The approver API call transitions the session to Approved and records the approver.'
  printf '%s\n' '$ POST /api/breakglassSessions/{name}/approve'
  approval_payload='{"reason":"INC-DEMO-001 verified; temporary access approved"}'
  api_request "$APPROVER_TOKEN" POST \
    "/api/breakglassSessions/${SESSION_NAME}/approve?namespace=${NAMESPACE}" \
    "$approval_payload"
  expect_status 200
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq '{name: .metadata.name, state: .status.state, approver: .status.approver}' \
    <<<"$LAST_BODY"
  wait_for_breakglass_state Approved
  sleep "$DEMO_PAUSE"

  step \
    '5. The same protected request is now allowed' \
    'The webhook recognizes the approved temporary group and allows the Kubernetes request.'
  printf '%s\n' '$ POST /api/breakglass/webhook/authorize/tenant-a (get configmaps)'
  webhook_request get configmaps
  expect_status 200
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq '{allowed: .status.allowed, reason: .status.reason}' <<<"$LAST_BODY"
  printf '%s\n' 'After state: the same request is now allowed by the approved session.'
  sleep "$DEMO_PAUSE"

  step \
    '6. Explicit deny policy still overrides an active session' \
    'DenyPolicy precedence remains enforced even when the BreakglassSession is active.'
  printf '%s\n' '$ POST /api/breakglass/webhook/authorize/tenant-a (get secrets)'
  webhook_request get secrets
  expect_status 200
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq '{allowed: .status.allowed, reason: .status.reason}' <<<"$LAST_BODY"
  printf '%s\n' 'Approved session + matching DenyPolicy -> explicit policy denial still wins.'
  sleep "$DEMO_PAUSE"

  step \
    '7. The requester reads the approved session through the REST API' \
    'The session detail API exposes state, requester, granted group, and expiry for auditability.'
  printf '%s\n' '$ GET /api/breakglassSessions/{name}'
  api_request "$REQUESTER_TOKEN" GET \
    "/api/breakglassSessions/${SESSION_NAME}?namespace=${NAMESPACE}"
  expect_status 200
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq '(.session // .) | {
    name: .metadata.name,
    state: .status.state,
    requestedBy: .spec.user,
    grantedGroup: .spec.grantedGroup,
    expiresAt: .status.expiresAt
  }' <<<"$LAST_BODY"
  printf '%s\n' 'DebugSession transition: created as Pending, then observed as Active.'
  sleep "$DEMO_PAUSE"

  step \
    '8. A developer discovers debug-session templates' \
    'The template API exposes the permitted debug mode, namespace, and duration constraints.'
  printf '%s\n' '$ GET /api/debugSessions/templates'
  api_request "$DEBUG_TOKEN" GET /api/debugSessions/templates
  expect_status 200
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq '{total, templates: [.templates[] | {
    name,
    displayName,
    requiresApproval,
    targetNamespace
  }]}' <<<"$LAST_BODY"
  sleep "$DEMO_PAUSE"

  step \
    '9. The developer creates a temporary DebugSession' \
    'The API creates a controlled debug workload request with a bounded duration.'
  printf '%s\n' '$ POST /api/debugSessions'
  debug_payload="$(jq -n \
    '{
      templateRef: "breakglass-dev-debug-template",
      cluster: "breakglass-hub",
      requestedDuration: "20m",
      targetNamespace: "breakglass-debug",
      reason: "INC-DEMO-001: inspect the network path"
    }')"
  api_request "$DEBUG_TOKEN" POST /api/debugSessions "$debug_payload"
  expect_status 201
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq '{
    name: .metadata.name,
    state: (.status.state // "Pending"),
    templateRef: .spec.templateRef,
    cluster: .spec.cluster,
    targetNamespace: .spec.targetNamespace
  }' <<<"$LAST_BODY"
  DEBUG_SESSION_NAME="$(jq -er '.metadata.name' <<<"$LAST_BODY")"
  wait_for_debug_state Active
  sleep "$DEMO_PAUSE"

  step \
    '10. The active DebugSession is available through the REST API' \
    'The detail API reports the active state, target cluster, namespace, and expiry.'
  printf '%s\n' '$ GET /api/debugSessions/{name}'
  printf 'HTTP %s\n' "$LAST_STATUS"
  jq '{
    name: .metadata.name,
    state: .status.state,
    requestedBy: (.spec.requestedBy // .status.requestedBy),
    cluster: .spec.cluster,
    templateRef: .spec.templateRef,
    targetNamespace: .spec.targetNamespace,
    expiresAt: .status.expiresAt
  }' <<<"$LAST_BODY"
  sleep "$DEMO_PAUSE"

  printf '\n%s\n' 'Demo complete. Temporary sessions are cleaned up after recording.'
}

main() {
  if [[ "${1:-}" == "--play" ]]; then
    run_demo
    return
  fi

  load_e2e_environment
  require_commands
  command -v asciinema >/dev/null 2>&1 || die "required command not found: asciinema"
  check_services
  mkdir -p "$(dirname "$RECORDING_FILE")"
  apply_demo_escalation
  trap cleanup_escalation EXIT
  export DEMO_ESCALATION_NAME

  asciinema record \
    --quiet \
    --headless \
    --return \
    --overwrite \
    --window-size 110x34 \
    --idle-time-limit 3 \
    --title "Breakglass user journey: deny, approve, API access, DebugSession" \
    --command "$PLAY_SCRIPT --play" \
    "$RECORDING_FILE"

  printf 'Recording written to %s\n' "$RECORDING_FILE"
}

main "$@"
