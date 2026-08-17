#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PLAY_SCRIPT="${ROOT_DIR}/e2e/record-breakglass-sync-console.sh"
CAST_FILE="${BREAKGLASS_SYNC_CONSOLE_CAST:-${ROOT_DIR}/docs/demos/breakglass-sync-console.cast}"
SEGMENTS_FILE="${BREAKGLASS_UI_SEGMENTS_FILE:-}"
BGCTL_BIN="${BGCTL_BIN:-${ROOT_DIR}/bin/bgctl}"

API_BASE="${BREAKGLASS_API_URL:-http://localhost:8080}"
API_BASE="${API_BASE%/}"
KEYCLOAK_PORT="${KEYCLOAK_PORT:-8443}"
KEYCLOAK_ISSUER_HOST="${KEYCLOAK_ISSUER_HOST:-breakglass-keycloak.breakglass-system.svc.cluster.local:8443}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-breakglass-hub}"
DEBUG_NAMESPACE=breakglass-debug
CLUSTER_NAME=breakglass-hub
GROUP_NAME=breakglass-emergency-admin
DEBUG_TEMPLATE=breakglass-dev-debug-template
UI_SLOWDOWN="${BREAKGLASS_UI_SLOWDOWN:-2}"

REQUESTER_USERNAME=ops-user-gamma
REQUESTER_PASSWORD=ops-gamma-password
APPROVER_USERNAME=approver-security
APPROVER_PASSWORD=approver-security-password

REQUESTER_TOKEN=
APPROVER_TOKEN=
SESSION_NAME=
DEBUG_SESSION_NAME=
SEGMENT_DURATIONS=()

die() {
  printf 'sync-console: %s\n' "$*" >&2
  exit 1
}

load_environment() {
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

require_commands() {
  local command
  for command in asciinema curl ffprobe jq kubectl python3; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
  done
  [[ -x "$BGCTL_BIN" ]] || die "bgctl binary not found or not executable: $BGCTL_BIN"
  [[ -n "$SEGMENTS_FILE" && -s "$SEGMENTS_FILE" ]] ||
    die "BREAKGLASS_UI_SEGMENTS_FILE must point to the completed UI segments"
}

get_token() {
  HOST_HEADER="$KEYCLOAK_ISSUER_HOST" \
    PORT="$KEYCLOAK_PORT" \
    "$ROOT_DIR/e2e/get-token.sh" "$1" "$2"
}

run_as_requester() {
  "$BGCTL_BIN" --server "$API_BASE" --token "$REQUESTER_TOKEN" --non-interactive "$@"
}

run_as_approver() {
  "$BGCTL_BIN" --server "$API_BASE" --token "$APPROVER_TOKEN" --non-interactive "$@"
}

run_kubectl() {
  env -u KUBECONFIG kubectl --context "$KUBECTL_CONTEXT" "$@"
}

now() {
  python3 -c 'import time; print(time.monotonic())'
}

sleep_remaining() {
  local started="$1"
  local target="$2"
  local elapsed
  elapsed="$(python3 - "$started" "$target" <<'PY'
import sys
import time

started = float(sys.argv[1])
target = float(sys.argv[2])
print(max(0.0, target - (time.monotonic() - started)))
PY
)"
  sleep "$elapsed"
}

load_segment_durations() {
  local name path raw_duration
  while IFS=$'\t' read -r name path; do
    [[ -f "$path" ]] || die "missing UI segment ${name}: ${path}"
    raw_duration="$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$path")"
    SEGMENT_DURATIONS+=("$(python3 - "$raw_duration" "$UI_SLOWDOWN" <<'PY'
import sys

print(float(sys.argv[1]) * float(sys.argv[2]))
PY
)")
  done <"$SEGMENTS_FILE"
  [[ "${#SEGMENT_DURATIONS[@]}" -eq 4 ]] ||
    die "expected four UI segments, got ${#SEGMENT_DURATIONS[@]}"
}

wait_for_session_state() {
  local expected="$1"
  local output=
  local state=
  for _ in $(seq 1 60); do
    if output="$(run_as_requester session get "$SESSION_NAME" -o json 2>/dev/null)"; then
      state="$(jq -r '.status.state // empty' <<<"$output")"
      [[ "$state" == "$expected" ]] && return
    fi
    sleep 1
  done
  die "session ${SESSION_NAME} did not reach ${expected}"
}

wait_for_debug_state() {
  local expected="$1"
  local output=
  local state=
  for _ in $(seq 1 90); do
    if output="$(run_as_requester debug session get "$DEBUG_SESSION_NAME" -o json 2>/dev/null)"; then
      state="$(jq -r '.status.state // empty' <<<"$output")"
      [[ "$state" == "$expected" ]] && return
      [[ "$state" == "Failed" ]] && die "DebugSession failed: ${output}"
    fi
    sleep 2
  done
  die "DebugSession ${DEBUG_SESSION_NAME} did not reach ${expected}"
}

cleanup() {
  if [[ -n "$DEBUG_SESSION_NAME" && -n "$REQUESTER_TOKEN" ]]; then
    run_as_requester debug session terminate "$DEBUG_SESSION_NAME" --yes >/dev/null 2>&1 || true
  fi
  if [[ -n "$SESSION_NAME" && -n "$REQUESTER_TOKEN" ]]; then
    run_as_requester session drop "$SESSION_NAME" --yes >/dev/null 2>&1 || true
    run_as_requester session withdraw "$SESSION_NAME" >/dev/null 2>&1 || true
  fi
}

cleanup_existing_sessions() {
  local sessions name state
  sessions="$(run_as_requester session list --mine -o json 2>/dev/null || printf '[]')"
  while IFS=$'\t' read -r name state; do
    [[ -n "$name" ]] || continue
    case "$state" in
      Approved|Active)
        run_as_requester session drop "$name" --yes >/dev/null 2>&1 || true
        ;;
      Pending)
        run_as_requester session withdraw "$name" >/dev/null 2>&1 || true
        ;;
    esac
  done < <(
    jq -r --arg cluster "$CLUSTER_NAME" --arg group "$GROUP_NAME" '
      .[] | select(.spec.cluster == $cluster and .spec.grantedGroup == $group)
      | [.metadata.name, .status.state] | @tsv
    ' <<<"$sessions"
  )
}

run_console() {
  load_environment
  require_commands
  load_segment_durations
  trap cleanup EXIT

  REQUESTER_TOKEN="$(get_token "$REQUESTER_USERNAME" "$REQUESTER_PASSWORD")"
  APPROVER_TOKEN="$(get_token "$APPROVER_USERNAME" "$APPROVER_PASSWORD")"
  cleanup_existing_sessions

  printf '%s\n' 'Synchronized console verification track'
  printf '%s\n' 'The four chapters align with the four browser chapters on the left.'
  printf '%s\n' 'This console uses real bgctl and kubectl calls against the E2E cluster.'

  started="$(now)"
  printf '\n%s\n' 'Chapter 1/4 - Requester pending'
  printf '%s\n' 'Before approval: identify the user, inspect the API server, and show no temporary grant.'
  printf '%s\n' '$ kubectl auth whoami --as=ops-gamma@example.com --as-group=ops'
  run_kubectl auth whoami --as=ops-gamma@example.com --as-group=ops --as-group=system:authenticated -o yaml
  printf '%s\n' '$ kubectl get --raw /version'
  run_kubectl get --raw /version | jq '{gitVersion, major, minor}'
  printf '%s\n' '$ bgctl escalation list -o table'
  run_as_requester escalation list -o table | sed -n '1,18p'
  printf '%s\n' '$ kubectl auth can-i get configmaps --as=ops-gamma@example.com --as-group=ops'
  before_access="$(run_kubectl auth can-i get configmaps --namespace default --as=ops-gamma@example.com --as-group=ops --as-group=system:authenticated 2>/dev/null || true)"
  printf '%s\n' "$before_access" | awk '{print $1}'
  printf '%s\n' 'Before: no approved session, so access is not granted.'
  sleep_remaining "$started" "${SEGMENT_DURATIONS[0]}"

  started="$(now)"
  printf '\n%s\n' 'Chapter 2/4 - Approver approval'
  printf '%s\n' 'The UI request is now pending; the console verifies the same approval state transition.'
  printf '%s\n' '$ bgctl session list --mine --state Pending,Approved -o wide'
  run_as_requester session list --mine --state Pending,Approved -o wide | sed -n '1,14p'
  session_output="$(run_as_requester session request --cluster "$CLUSTER_NAME" --group "$GROUP_NAME" --reason "INC-SYNC-DEMO: console approval track" -o json)"
  SESSION_NAME="$(jq -er '.metadata.name' <<<"$session_output")"
  wait_for_session_state Pending
  printf '%s\n' '$ bgctl session get SESSION_NAME -o table'
  run_as_requester session get "$SESSION_NAME" -o table | sed -n '1,18p'
  run_as_approver session approve "$SESSION_NAME" --reason "Approved for synchronized console demo" >/dev/null
  wait_for_session_state Approved
  printf '%s\n' 'After: Pending -> Approved; the approver is recorded and expiry is active.'
  sleep_remaining "$started" "${SEGMENT_DURATIONS[1]}"

  started="$(now)"
  printf '\n%s\n' 'Chapter 3/4 - Requester granted'
  printf '%s\n' 'The UI shows the approved request while the console verifies Kubernetes access.'
  printf '%s\n' '$ bgctl session get SESSION_NAME -o table'
  run_as_requester session get "$SESSION_NAME" -o table | sed -n '1,18p'
  printf '%s\n' '$ kubectl auth can-i get configmaps --as=ops-gamma@example.com --as-group=breakglass-emergency-admin'
  run_kubectl auth can-i get configmaps --namespace default --as=ops-gamma@example.com --as-group=ops --as-group="$GROUP_NAME" --as-group=system:authenticated
  printf '%s\n' '$ kubectl get configmaps --as=ops-gamma@example.com --as-group=breakglass-emergency-admin'
  run_kubectl get configmaps --namespace default --as=ops-gamma@example.com --as-group=ops --as-group="$GROUP_NAME" --as-group=system:authenticated --ignore-not-found -o name | head -10
  printf '%s\n' 'After: can-i is yes and the Kubernetes API returns a ConfigMap.'
  sleep_remaining "$started" "${SEGMENT_DURATIONS[2]}"

  started="$(now)"
  printf '\n%s\n' 'Chapter 4/4 - DebugSession diagnostics'
  printf '%s\n' 'The UI creates a DebugSession while the console observes its pod and runs tcpdump.'
  REQUESTER_TOKEN="$(get_token "$REQUESTER_USERNAME" "$REQUESTER_PASSWORD")"
  printf '%s\n' '$ bgctl debug template list -o table'
  run_as_requester debug template list -o table | sed -n '1,18p'
  debug_output="$(run_as_requester debug session create --template "$DEBUG_TEMPLATE" --cluster "$CLUSTER_NAME" --duration 20m --target-namespace "$DEBUG_NAMESPACE" --reason "INC-SYNC-DEMO: network diagnostics" -o json)"
  DEBUG_SESSION_NAME="$(jq -er '.metadata.name' <<<"$debug_output")"
  wait_for_debug_state Active
  printf '%s\n' '$ bgctl debug session get DEBUG_SESSION_NAME -o table'
  run_as_requester debug session get "$DEBUG_SESSION_NAME" -o table | sed -n '1,18p'
  debug_pod_name=
  for _ in $(seq 1 90); do
    debug_pod_name="$(run_kubectl get pods --namespace "$DEBUG_NAMESPACE" --selector "breakglass.telekom.com/debug-session=${DEBUG_SESSION_NAME}" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    [[ -n "$debug_pod_name" ]] && break
    sleep 2
  done
  [[ -n "$debug_pod_name" ]] || die "debug pod did not reach Running"
  printf '%s\n' '$ kubectl get pods -n breakglass-debug'
  run_kubectl get pods --namespace "$DEBUG_NAMESPACE" --selector "breakglass.telekom.com/debug-session=${DEBUG_SESSION_NAME}" --field-selector=status.phase=Running -o custom-columns='NAME:.metadata.name,READY:.status.containerStatuses[0].ready,STATUS:.status.phase'
  printf '%s\n' '$ kubectl exec DEBUG_POD -- tcpdump -D'
  run_kubectl exec --namespace "$DEBUG_NAMESPACE" "$debug_pod_name" -- tcpdump -D | head -n 8
  printf '%s\n' 'After: DebugSession is Active, its pod is Running, and tcpdump is available.'
  sleep_remaining "$started" "${SEGMENT_DURATIONS[3]}"
}

main() {
  if [[ "${1:-}" == "--play" ]]; then
    run_console
    return
  fi

  load_environment
  require_commands
  mkdir -p "$(dirname "$CAST_FILE")"
  asciinema record \
    --quiet \
    --headless \
    --return \
    --overwrite \
    --window-size 90x32 \
    --idle-time-limit 3 \
    --title "Synchronized Breakglass console verification" \
    --command "$PLAY_SCRIPT --play" \
    "$CAST_FILE"
}

main "$@"
