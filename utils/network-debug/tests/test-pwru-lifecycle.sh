#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

cat >"$fixture/docker" <<'EOF'
#!/bin/sh
set -eu
state=$PWRU_FAKE_STATE
command=${1:-}
shift || true
case "$command" in
  inspect)
    format=''
    if [ "${1:-}" = --format ]; then
      format=$2
      shift 2
    fi
    name=${1:-}
    [ "$name" = "$PWRU_FAKE_CONTAINER" ] && [ -f "$state" ] || exit 1
    case "$format" in
      *State.Status*) cat "$state" | sed -n '1p' ;;
      *State.ExitCode*) cat "$state" | sed -n '2p' ;;
      *) exit 0 ;;
    esac
    ;;
  cp)
    source=$1
    target=$2
    [ -f "$PWRU_FAKE_LOG" ] || exit 1
    case "$source" in
      "$PWRU_FAKE_CONTAINER":/work/pwru.log) cp "$PWRU_FAKE_LOG" "$target" ;;
      *) exit 1 ;;
    esac
    ;;
  kill)
    signal=$2
    name=$3
    [ "$name" = "$PWRU_FAKE_CONTAINER" ] && [ -f "$state" ] || exit 1
    printf '%s\n' "$signal" >>"$PWRU_FAKE_SIGNALS"
    if [ "$signal" = KILL ]; then
      rm -f "$state"
    elif [ "$PWRU_FAKE_MODE" = graceful ]; then
      { printf '%s\n' exited; printf '%s\n' 0; } >"$state"
    fi
    ;;
  rm)
    name=$2
    [ "$name" = "$PWRU_FAKE_CONTAINER" ] && [ -f "$state" ] || exit 1
    if [ "$PWRU_FAKE_MODE" = stuck ] && [ ! -f "$PWRU_FAKE_RM_ATTEMPTED" ]; then
      : >"$PWRU_FAKE_RM_ATTEMPTED"
      exit 1
    fi
    rm -f "$state"
    ;;
  info) ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fixture/docker"

run_case() {
	local mode=$1 log_content=$2 expected_wait=$3 expected_stop=$4
	local expected_signals=INT
	local state="$fixture/state" output="$fixture/output" signals="$fixture/signals"
	[ "$mode" = stuck ] && expected_signals='INT
KILL'
	printf '%s\n%s\n' running 0 >"$state"
	printf '%s\n' "$log_content" >"$fixture/pwru.log"
	: >"$signals"
	rm -f "$fixture/rm-attempted" "$output"
	if PWRU_FAKE_MODE="$mode" PWRU_FAKE_STATE="$state" PWRU_FAKE_LOG="$fixture/pwru.log" \
		PWRU_FAKE_SIGNALS="$signals" PWRU_FAKE_RM_ATTEMPTED="$fixture/rm-attempted" \
		PWRU_FAKE_CONTAINER=pwru-proof PATH="$fixture:/usr/bin:/bin" \
		bash -c '
			set -u
			. "$1/pwru-lifecycle.sh"
			wait_status=0
			pwru_wait_for_event "$2" "$3" 1 "127\\.0\\.0\\.1.*->.*127\\.0\\.0\\.1" || wait_status=$?
			test "$wait_status" -eq "$4"
			stop_status=0
			pwru_stop_gracefully "$2" 1 || stop_status=$?
			test "$stop_status" -eq "$5"
			test "$(cat "$PWRU_FAKE_SIGNALS")" = "$6"
			if [ "$7" = true ]; then
				pwru_force_remove "$2"
				test ! -e "$PWRU_FAKE_STATE"
			fi
		' bash "$root" pwru-proof "$output" "$expected_wait" "$expected_stop" "$expected_signals" "$([ "$mode" = stuck ] && printf true || printf false)"; then
		:
	else
		printf '%s\n' "pwru lifecycle case $mode failed" >&2
		exit 1
	fi
}

run_case graceful '127.0.0.1:12345 -> 127.0.0.1:18080' 0 0
run_case stuck 'pwru started without a packet tuple' 1 2

printf '%s\n' 'pwru lifecycle behavior checks passed'
