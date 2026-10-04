#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Usage: start_keepalive_port_forward namespace service localPort remotePort [kubeconfig] [stderr]
start_keepalive_port_forward() {
  local namespace="$1" service="$2" local_port="$3" remote_port="$4"
  local kubeconfig="${5:-${HUB_KUBECONFIG:-${KUBECONFIG:-}}}"
  local stderr="${6:-/dev/null}"
  (
    set +e
    local child_pid=""
    # shellcheck disable=SC2317
    stop_forward() {
      trap - EXIT TERM INT
      if [ -n "$child_pid" ]; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
      fi
      exit 0
    }
    trap 'stop_forward' EXIT TERM INT
    while true; do
      KUBECONFIG="$kubeconfig" "${KUBECTL:-kubectl}" -n "$namespace" \
        port-forward "svc/$service" "$local_port:$remote_port" 2>>"$stderr" &
      child_pid=$!
      wait "$child_pid"
      printf '[keepalive] %s port-forward exited, restarting in 2s...\n' "$service" >&2
      sleep 2 &
      child_pid=$!
      wait "$child_pid"
    done
  ) &
  local pid=$!
  if [ -n "${PF_FILE:-}" ]; then
    if ! { mkdir -p "$(dirname "$PF_FILE")" && printf '%s\n' "$pid" >> "$PF_FILE"; }; then
      kill "$pid"
      wait "$pid" 2>/dev/null || true
      return 1
    fi
  fi
  printf '%s\n' "$pid"
}
