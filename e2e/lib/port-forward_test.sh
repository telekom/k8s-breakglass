#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
# shellcheck source=e2e/lib/port-forward.sh
source "$(dirname "${BASH_SOURCE[0]}")/port-forward.sh"

test_dir="$(mktemp -d)"
wrapper_pid=""
cleanup() {
  if [ -n "$wrapper_pid" ]; then
    kill "$wrapper_pid" 2>/dev/null || true
    wait "$wrapper_pid" 2>/dev/null || true
  fi
  rm -rf "$test_dir"
}
trap cleanup EXIT

kubectl() {
  printf '%s|%s\n' "${KUBECONFIG:-}" "$*" >> "$test_dir/calls"
  if [ "$mode" = fail ] || { [ "$mode" = restart ] && [ ! -f "$test_dir/failed" ]; }; then
    : > "$test_dir/failed"
    return 1
  fi
  exec bash -c 'printf "%s\n" "$$" > "$1"; exec sleep 30' bash "$test_dir/child"
}

wait_for_calls() {
  local expected="$1"
  for _ in {1..100}; do
    if [ -f "$test_dir/calls" ] && [ "$(wc -l < "$test_dir/calls")" -ge "$expected" ] &&
      { [ "$mode" = fail ] || [ -f "$test_dir/child" ]; }; then
      return 0
    fi
    sleep 0.05
  done
  cat "$test_dir/forward.log" >&2
  return 1
}

stop_and_check() {
  local child="$1"
  kill "$wrapper_pid"
  wait "$wrapper_pid"
  wrapper_pid=""
  ! kill -0 "$child" 2>/dev/null
}

for configuration in explicit hub ambient; do
  rm -f "$test_dir/calls" "$test_dir/failed" "$test_dir/child"
  mode=restart
  KUBECONFIG=ambient-config
  export HUB_KUBECONFIG=hub-config
  PF_FILE="$test_dir/pids"
  config_override=""
  case "$configuration" in
    explicit) config_override=explicit-config; expected_config=explicit-config ;;
    hub) expected_config=hub-config ;;
    ambient) unset HUB_KUBECONFIG; expected_config=ambient-config ;;
  esac
  start_keepalive_port_forward test-ns test-service 8080 9090 "$config_override" > "$test_dir/pid-output" 2> "$test_dir/forward.log"
  wrapper_pid=$!
  wait_for_calls 2
  expected="$expected_config|-n test-ns port-forward svc/test-service 8080:9090"
  test "$(head -n 1 "$test_dir/calls")" = "$expected"
  test "$(tail -n 1 "$test_dir/calls")" = "$expected"
  test "$(tail -n 1 "$PF_FILE")" = "$wrapper_pid"
  test "$(cat "$test_dir/pid-output")" = "$wrapper_pid"
  child="$(cat "$test_dir/child")"
  kill -0 "$wrapper_pid"
  kill -0 "$child"
  stop_and_check "$child"
done

# A stop during the restart delay must not leave the delay process behind.
rm -f "$test_dir/calls"
mode=fail
unset PF_FILE
start_keepalive_port_forward test-ns test-service 8080 9090 > "$test_dir/forward.log" 2>&1
wrapper_pid=$!
wait_for_calls 1
sleep 0.1
delay_pid="$(ps -axo pid=,ppid= | awk -v parent="$wrapper_pid" '$2 == parent {print $1}')"
test -n "$delay_pid"
stop_and_check "$delay_pid"

# Failure to record ownership must stop the wrapper instead of leaking it.
printf 'not a directory\n' > "$test_dir/not-directory"
PF_FILE="$test_dir/not-directory/pids"
if start_keepalive_port_forward test-ns test-service 8080 9090 > "$test_dir/forward.log" 2>&1; then
  exit 1
fi
if kill -0 "$!" 2>/dev/null; then
  exit 1
fi

printf '%s\n' 'Port-forward restart, kubeconfig, PID tracking, and cleanup behavior passed'
