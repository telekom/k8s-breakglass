#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PLAY_SCRIPT="${ROOT_DIR}/e2e/record-breakglass-cli-demo.sh"
RECORDING_FILE="${BREAKGLASS_CLI_DEMO_RECORDING:-${ROOT_DIR}/docs/demos/breakglass-user-flow.cast}"
BGCTL_BIN="${BGCTL_BIN:-${ROOT_DIR}/bin/bgctl}"

API_BASE="${BREAKGLASS_API_URL:-http://localhost:8080}"
API_BASE="${API_BASE%/}"
KEYCLOAK_PORT="${KEYCLOAK_PORT:-8443}"
KEYCLOAK_ISSUER_HOST="${KEYCLOAK_ISSUER_HOST:-breakglass-keycloak.breakglass-system.svc.cluster.local:8443}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-breakglass-hub}"
DEBUG_NAMESPACE=breakglass-debug

REQUESTER_USERNAME=ops-user-gamma
REQUESTER_PASSWORD=ops-gamma-password
APPROVER_USERNAME=approver-security
APPROVER_PASSWORD=approver-security-password
CLUSTER_NAME=breakglass-hub
GROUP_NAME=breakglass-emergency-admin
DEBUG_TEMPLATE=breakglass-dev-debug-template
DEMO_PAUSE="${BREAKGLASS_DEMO_PAUSE:-2}"

REQUESTER_TOKEN=
APPROVER_TOKEN=
SESSION_NAME=
DEBUG_SESSION_NAME=

die() {
  printf 'cli-demo: %s\n' "$*" >&2
  exit 1
}

step() {
  printf '\n%s\n' "$1"
  printf 'What this proves: %s\n' "$2"
  sleep "$DEMO_PAUSE"
}

require_commands() {
  local command
  for command in curl jq asciinema kubectl; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
  done
  [[ -x "$BGCTL_BIN" ]] || die "bgctl binary not found or not executable: $BGCTL_BIN"
}

load_e2e_environment() {
  local env_file="${ROOT_DIR}/e2e/kind-setup-single-tdir/e2e-env.sh"
  if [[ -f "$env_file" ]]; then
    # shellcheck disable=SC1090
    source "$env_file"
  fi
  API_BASE="${BREAKGLASS_API_URL:-$API_BASE}"
  API_BASE="${API_BASE%/}"
  KEYCLOAK_PORT="${KEYCLOAK_PORT:-8443}"
  KEYCLOAK_ISSUER_HOST="${KEYCLOAK_ISSUER_HOST:-breakglass-keycloak.breakglass-system.svc.cluster.local:8443}"
}

check_services() {
  curl -fsS "${API_BASE}/api/config" >/dev/null ||
    die "Breakglass API is not reachable at ${API_BASE}"
  curl -kfsS "https://localhost:${KEYCLOAK_PORT}" >/dev/null ||
    die "Keycloak is not reachable on port ${KEYCLOAK_PORT}"
  run_kubectl get namespace default >/dev/null ||
    die "Kubernetes API is not reachable through context ${KUBECTL_CONTEXT}"
}

get_token() {
  HOST_HEADER="$KEYCLOAK_ISSUER_HOST" \
    PORT="$KEYCLOAK_PORT" \
    "$ROOT_DIR/e2e/get-token.sh" "$1" "$2"
}

run_as_requester() {
  "$BGCTL_BIN" \
    --server "$API_BASE" \
    --token "$REQUESTER_TOKEN" \
    --non-interactive \
    "$@"
}

run_as_approver() {
  "$BGCTL_BIN" \
    --server "$API_BASE" \
    --token "$APPROVER_TOKEN" \
    --non-interactive \
    "$@"
}

run_kubectl() {
  env -u KUBECONFIG kubectl --context "$KUBECTL_CONTEXT" "$@"
}

wait_for_session_state() {
  local expected="$1"
  local state=
  local output=

  for _ in $(seq 1 60); do
    if output="$(run_as_requester session get "$SESSION_NAME" -o json 2>/dev/null)"; then
      state="$(jq -r '.status.state // empty' <<<"$output")"
      if [[ "$state" == "$expected" ]]; then
        return
      fi
    fi
    sleep 1
  done

  printf 'Timed out waiting for session %s to become %s\n' "$SESSION_NAME" "$expected" >&2
  exit 1
}

wait_for_debug_state() {
  local expected="$1"
  local state=
  local output=

  for _ in $(seq 1 90); do
    if output="$(run_as_requester debug session get "$DEBUG_SESSION_NAME" -o json 2>/dev/null)"; then
      state="$(jq -r '.status.state // empty' <<<"$output")"
      if [[ "$state" == "$expected" ]]; then
        return
      fi
      if [[ "$state" == "Failed" ]]; then
        printf 'DebugSession failed:\n%s\n' "$output" >&2
        exit 1
      fi
    fi
    sleep 2
  done

  printf 'Timed out waiting for DebugSession %s to become %s\n' \
    "$DEBUG_SESSION_NAME" "$expected" >&2
  exit 1
}

cleanup_demo() {
  if [[ -n "$DEBUG_SESSION_NAME" && -n "$REQUESTER_TOKEN" ]]; then
    run_as_requester debug session terminate "$DEBUG_SESSION_NAME" --yes >/dev/null 2>&1 || true
  fi
  if [[ -n "$SESSION_NAME" && -n "$REQUESTER_TOKEN" ]]; then
    run_as_requester session drop "$SESSION_NAME" --yes >/dev/null 2>&1 || true
    run_as_requester session withdraw "$SESSION_NAME" >/dev/null 2>&1 || true
  fi
}

run_demo() {
  load_e2e_environment
  require_commands
  check_services
  trap cleanup_demo EXIT

  REQUESTER_TOKEN="$(get_token "$REQUESTER_USERNAME" "$REQUESTER_PASSWORD")"
  APPROVER_TOKEN="$(get_token "$APPROVER_USERNAME" "$APPROVER_PASSWORD")"

  printf '%s\n' 'Breakglass CLI user journey'
  printf '%s\n' 'CLI: bgctl | API: http://localhost:8080 | Cluster: breakglass-hub'
  printf '%s\n' 'Credentials are held in memory and are not printed.'
  sleep "$DEMO_PAUSE"

  step \
    '1. CLI rejects an unauthorized escalation request' \
    'The API refuses a group that this requester is not allowed to request.'
  printf '%s\n' '$ bgctl session request --cluster breakglass-hub --group cluster-admin-access'
  if denied_output="$(
    run_as_requester session request \
      --cluster "$CLUSTER_NAME" \
      --group cluster-admin-access \
      --reason "INC-CLI-DEMO-001: unauthorized request" 2>&1
  )"; then
    die "unauthorized request unexpectedly succeeded"
  else
    printf '%s\n' 'Expected denial (HTTP 403): requester is not authorized for the requested group.'
  fi
  sleep "$DEMO_PAUSE"

  step \
    '2. Requester lists available escalation policies' \
    'The requester can discover the approved escalation, target clusters, and approver groups.'
  printf '%s\n' '$ bgctl escalation list -o json'
  escalations="$(run_as_requester escalation list -o json)"
  jq --arg group "$GROUP_NAME" \
    '[.[] | select(.spec.escalatedGroup == $group) | {
      name: .metadata.name,
      escalatedGroup: .spec.escalatedGroup,
      clusters: .spec.allowed.clusters,
      approvers: .spec.approvers
    }]' <<<"$escalations"
  sleep "$DEMO_PAUSE"

  step \
    '3. kubectl shows the requester identity and access before approval' \
    'The Kubernetes identity is ops-gamma@example.com, but temporary access is not active yet.'
  printf '%s\n' 'The Kubernetes identity is still ops-gamma@example.com; Breakglass changes authorization only after approval.'
  printf '%s\n' '$ kubectl auth whoami --as=ops-gamma@example.com --as-group=ops'
  run_kubectl auth whoami \
    --as=ops-gamma@example.com \
    --as-group=ops \
    --as-group=system:authenticated \
    -o yaml
  printf '%s\n' '$ kubectl get --raw /version'
  run_kubectl get --raw /version | jq '{gitVersion, major, minor}'
  printf '%s\n' '$ kubectl auth can-i get configmaps --as=ops-gamma@example.com --as-group=ops'
  before_access="$(
    run_kubectl auth can-i get configmaps \
      --namespace default \
      --as=ops-gamma@example.com \
      --as-group=ops \
      --as-group=system:authenticated 2>/dev/null || true
  )"
  printf '%s\n' "$before_access" | awk '{print $1}'
  printf '%s\n' 'Explanation: no; the requester has no approved temporary grant yet.'
  sleep "$DEMO_PAUSE"

  step \
    '4. Requester creates a temporary session' \
    'bgctl submits a time-bounded BreakglassSession request with an incident reason.'
  printf '%s\n' '$ bgctl session request --cluster breakglass-hub --group breakglass-emergency-admin'
  session_output="$(
    run_as_requester session request \
      --cluster "$CLUSTER_NAME" \
      --group "$GROUP_NAME" \
      --reason "INC-CLI-DEMO-001: inspect the service configuration" \
      -o json
  )"
  SESSION_NAME="$(jq -er '.metadata.name' <<<"$session_output")"
  jq '{name: .metadata.name, state: .status.state, cluster: .spec.cluster, group: .spec.grantedGroup}' \
    <<<"$session_output"
  printf '%s\n' 'Before approval: state=Pending, Kubernetes access=not granted.'
  wait_for_session_state Pending
  sleep "$DEMO_PAUSE"

  step \
    '5. Approver approves the session' \
    'The requester cannot self-approve; a separate authorized approver must confirm the incident.'
  printf '%s\n' '$ bgctl session approve SESSION_NAME # requester self-approval attempt'
  if self_approval_output="$(
    run_as_requester session approve "$SESSION_NAME" --reason "Requester self-approval attempt" 2>&1
  )"; then
    die "self-approval unexpectedly succeeded"
  else
    printf '%s\n' 'Expected self-approval denial (HTTP 403): requester cannot approve their own session.'
  fi
  sleep "$DEMO_PAUSE"
  printf '%s\n' '$ bgctl session approve SESSION_NAME --reason "Approved for incident response"'
  run_as_approver session approve "$SESSION_NAME" \
    --reason "INC-CLI-DEMO-001 verified; approved for incident response" >/dev/null
  wait_for_session_state Approved
  printf '%s\n' 'After approval: state=Approved, Kubernetes access=temporarily granted.'
  printf '%s\n' 'Approval command completed: state=Approved'
  sleep "$DEMO_PAUSE"

  step \
    '6. Requester reads the active session and lists it' \
    'The requester can inspect the approver, expiry, granted group, and active session list.'
  printf '%s\n' '$ bgctl session get SESSION_NAME -o json'
  session_output="$(run_as_requester session get "$SESSION_NAME" -o json)"
  jq '{
    name: .metadata.name,
    state: .status.state,
    requestedBy: .spec.user,
    grantedGroup: .spec.grantedGroup,
    expiresAt: .status.expiresAt
  }' <<<"$session_output"
  printf '%s\n' '$ bgctl session list --mine -o json'
  run_as_requester session list --mine -o json |
    jq --arg name "$SESSION_NAME" \
      '[.[] | select(.metadata.name == $name) | {name: .metadata.name, state: .status.state}]'
  sleep "$DEMO_PAUSE"

  step \
    '7. kubectl sees the newly granted API access' \
    'The same identity now uses the approved Breakglass group for a Kubernetes API request.'
  printf '%s\n' '$ kubectl auth can-i get configmaps --as=ops-gamma@example.com --as-group=breakglass-emergency-admin'
  run_kubectl auth can-i get configmaps \
    --namespace default \
    --as=ops-gamma@example.com \
    --as-group=ops \
    --as-group="$GROUP_NAME" \
    --as-group=system:authenticated
  printf '%s\n' '$ kubectl get configmaps --as=ops-gamma@example.com --as-group=breakglass-emergency-admin'
  run_kubectl get configmaps \
    --namespace default \
    --as=ops-gamma@example.com \
    --as-group=ops \
    --as-group="$GROUP_NAME" \
    --as-group=system:authenticated \
    --ignore-not-found \
    -o name | head -10
  printf '%s\n' 'Authorization transition: can-i no before approval -> can-i yes after approval.'
  sleep "$DEMO_PAUSE"

  step \
    '8. Requester discovers debug templates' \
    'The developer can see the permitted DebugSession template, clusters, and constraints.'
  printf '%s\n' '$ bgctl debug template list -o json'
  run_as_requester debug template list -o json |
    jq --arg template "$DEBUG_TEMPLATE" \
      '[.[] | select(.name == $template) | {name, displayName, requiresApproval, allowedClusters, allowedGroups}]'
  sleep "$DEMO_PAUSE"

  step \
    '9. Requester creates and observes a DebugSession' \
    'bgctl requests a controlled debug workload in the breakglass-debug namespace.'
  printf '%s\n' '$ bgctl debug session create --template breakglass-dev-debug-template --cluster breakglass-hub'
  debug_output="$(
    run_as_requester debug session create \
      --template "$DEBUG_TEMPLATE" \
      --cluster "$CLUSTER_NAME" \
      --duration 20m \
      --target-namespace breakglass-debug \
      --reason "INC-CLI-DEMO-001: inspect the network path" \
      -o json
  )"
  DEBUG_SESSION_NAME="$(jq -er '.metadata.name' <<<"$debug_output")"
  jq '{
    name: .metadata.name,
    state: (.status.state // "Pending"),
    templateRef: .spec.templateRef,
    cluster: .spec.cluster,
    targetNamespace: .spec.targetNamespace
  }' <<<"$debug_output"
  wait_for_debug_state Active
  debug_output="$(run_as_requester debug session get "$DEBUG_SESSION_NAME" -o json)"
  jq '{
    name: .metadata.name,
    state: .status.state,
    requestedBy: (.spec.requestedBy // .spec.user // .status.requestedBy),
    cluster: .spec.cluster,
    expiresAt: .status.expiresAt
  }' <<<"$debug_output"
  printf '%s\n' 'DebugSession transition: state=Pending -> state=Active; pod access is now available.'
  sleep "$DEMO_PAUSE"

  step \
    '10. kubectl finds the spawned debug pod' \
    'The DebugSession controller creates a running pod that can be inspected through the Kubernetes API.'
  debug_pod_name=
  for _ in $(seq 1 90); do
    debug_pod_name="$(
      run_kubectl get pods \
        --namespace "$DEBUG_NAMESPACE" \
        --selector "breakglass.telekom.com/debug-session=${DEBUG_SESSION_NAME}" \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
    )"
    if [[ -n "$debug_pod_name" ]]; then
      break
    fi
    sleep 2
  done
  [[ -n "$debug_pod_name" ]] || die "debug pod did not reach Running state"
  printf '%s\n' "\$ kubectl get pods -n ${DEBUG_NAMESPACE} -l breakglass.telekom.com/debug-session=${DEBUG_SESSION_NAME}"
  run_kubectl get pods \
    --namespace "$DEBUG_NAMESPACE" \
    --selector "breakglass.telekom.com/debug-session=${DEBUG_SESSION_NAME}" \
    --field-selector=status.phase=Running \
    --as=ops-gamma@example.com \
    --as-group=ops \
    --as-group="$GROUP_NAME" \
    --as-group=system:authenticated \
    -o custom-columns='NAME:.metadata.name,READY:.status.containerStatuses[0].ready,STATUS:.status.phase'
  sleep "$DEMO_PAUSE"

  step \
    '11. kubectl uses the spawned debug pod for tcpdump diagnostics' \
    'The controlled netshoot pod provides tcpdump for network troubleshooting without host access.'
  printf '%s\n' "\$ kubectl exec -n ${DEBUG_NAMESPACE} ${debug_pod_name} -- tcpdump --version"
  run_kubectl exec \
    --namespace "$DEBUG_NAMESPACE" \
    "$debug_pod_name" \
    --as=ops-gamma@example.com \
    --as-group=ops \
    --as-group="$GROUP_NAME" \
    --as-group=system:authenticated \
    -- tcpdump --version | head -n 2
  printf '%s\n' "\$ kubectl exec -n ${DEBUG_NAMESPACE} ${debug_pod_name} -- tcpdump -D"
  run_kubectl exec \
    --namespace "$DEBUG_NAMESPACE" \
    "$debug_pod_name" \
    --as=ops-gamma@example.com \
    --as-group=ops \
    --as-group="$GROUP_NAME" \
    --as-group=system:authenticated \
    -- tcpdump -D | head -n 8
  sleep "$DEMO_PAUSE"

  step \
    '12. DebugSession lifecycle closes cleanly' \
    'The requester lists the session, terminates it deliberately, and verifies the terminal state.'
  printf '%s\n' '$ bgctl debug session list --mine -o table'
  run_as_requester debug session list --mine -o table | sed -n '1,14p'
  printf '%s\n' '$ bgctl debug session terminate DEBUG_SESSION_NAME --yes'
  run_as_requester debug session terminate "$DEBUG_SESSION_NAME" --yes >/dev/null
  printf '%s\n' '$ bgctl debug session get DEBUG_SESSION_NAME -o table'
  run_as_requester debug session get "$DEBUG_SESSION_NAME" -o table | sed -n '1,14p'
  printf '%s\n' 'DebugSession transition: Active -> Terminated; the controlled pod is revoked.'
  sleep "$DEMO_PAUSE"

  printf '\n%s\n' 'CLI demo complete. Temporary sessions are cleaned up after recording.'
}

main() {
  if [[ "${1:-}" == "--play" ]]; then
    run_demo
    return
  fi

  load_e2e_environment
  require_commands
  check_services
  mkdir -p "$(dirname "$RECORDING_FILE")"
  export BREAKGLASS_CLI_DEMO_RECORDING="$RECORDING_FILE"
  asciinema record \
    --quiet \
    --headless \
    --return \
    --overwrite \
    --window-size 110x34 \
    --idle-time-limit 3 \
    --title "Breakglass CLI user journey" \
    --command "$PLAY_SCRIPT --play" \
    "$RECORDING_FILE"
  printf 'Recording written to %s\n' "$RECORDING_FILE"
}

main "$@"
