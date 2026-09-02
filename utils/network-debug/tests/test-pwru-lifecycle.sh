#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

# The lifecycle fixture models Docker signal/wait behavior and is intentionally
# Linux-only. macOS Docker Desktop has different timeout and signal semantics;
# the required Linux CI job still runs the complete fixture below.
if [[ "$(uname -s)" != Linux ]]; then
	printf '%s\n' 'skipping Linux-only pwru lifecycle fixture on non-Linux host' >&2
	exit 0
fi

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
  container)
    subcommand=${1:-}
    [ "$subcommand" = ls ] || exit 2
    if [ "$PWRU_FAKE_MODE" = inspect-fail-listed ]; then
      printf '%s\n' "$PWRU_FAKE_CONTAINER"
    fi
    ;;
  inspect)
    case "$PWRU_FAKE_MODE" in
      inspect-fail-listed|inspect-fail-absent) exit 1 ;;
    esac
    format=''
    if [ "${1:-}" = --format ]; then
      format=$2
      shift 2
    fi
    name=${1:-}
    [ "$name" = "$PWRU_FAKE_CONTAINER" ] && [ -f "$state" ] || exit 1
    if [ "$PWRU_FAKE_MODE" = delayed-graceful-boundary ] && [ -f "$PWRU_FAKE_DETACH_PENDING" ] && [ "$(sed -n '1p' "$state")" = running ]; then
      count=0
      [ -f "$PWRU_FAKE_INSPECT_COUNT" ] && count=$(cat "$PWRU_FAKE_INSPECT_COUNT")
      count=$((count + 1))
      printf '%s\n' "$count" >"$PWRU_FAKE_INSPECT_COUNT"
      if [ "$count" -ge 3 ]; then
        { printf '%s\n' exited; printf '%s\n' 0; } >"$state"
      fi
    fi
    case "$format" in
      *State.Status*) sed -n '1p' "$state" ;;
      *State.ExitCode*) sed -n '2p' "$state" ;;
      *Config.Labels*) printf '%s\n' "${PWRU_FAKE_OWNER:-}" ;;
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
      if [ "$PWRU_FAKE_MODE" = stubborn ] && [ ! -f "$PWRU_FAKE_KILL_ATTEMPTED" ]; then
        : >"$PWRU_FAKE_KILL_ATTEMPTED"
      else
        rm -f "$state"
      fi
    elif [ "$PWRU_FAKE_MODE" = graceful ]; then
      { printf '%s\n' exited; printf '%s\n' 0; } >"$state"
    elif [ "$PWRU_FAKE_MODE" = signal-exit ]; then
      { printf '%s\n' exited; printf '%s\n' 130; } >"$state"
    elif [ "$PWRU_FAKE_MODE" = delayed-graceful ] || [ "$PWRU_FAKE_MODE" = delayed-graceful-boundary ]; then
      delay=1
      if [ "$PWRU_FAKE_MODE" = delayed-graceful-boundary ]; then
        : >"$PWRU_FAKE_DETACH_PENDING"
      else
        (sleep "$delay"; { printf '%s\n' exited; printf '%s\n' 0; } >"${state}.next"; mv "${state}.next" "$state") &
      fi
    fi
    ;;
  wait)
    name=${1:-}
    [ "$name" = "$PWRU_FAKE_CONTAINER" ] && [ -f "$state" ] || exit 1
    printf '%s\n' "$name" >>"$PWRU_FAKE_WAIT_LOG"
    case "$PWRU_FAKE_MODE" in
      delayed-graceful|delayed-graceful-boundary)
        # Model the real pwru behavior where SIGINT is acknowledged first and
        # BPF detachment completes shortly afterwards.
        if [ "$PWRU_FAKE_MODE" = delayed-graceful-boundary ]; then
          # Keep the primary wait beyond its one-second bound. The inspect
          # fixture transitions after three settle polls, modelling a detach
          # completing just after the primary deadline without background jobs.
          sleep 2
          exit 124
        fi
        sleep 1
        { printf '%s\n' exited; printf '%s\n' 0; } >"$state"
        ;;
      stuck|stubborn)
        # Report the bounded wait outcome while retaining the running state;
        # this lets the helper exercise its timeout failure path portably.
        exit 124
        ;;
    esac
    [ -f "$state" ] || exit 1
    sed -n '2p' "$state"
    ;;
  rm)
    name=$2
    [ "$name" = "$PWRU_FAKE_CONTAINER" ] && [ -f "$state" ] || exit 1
    if [ "$PWRU_FAKE_MODE" = stuck ] && [ ! -f "$PWRU_FAKE_RM_ATTEMPTED" ]; then
      : >"$PWRU_FAKE_RM_ATTEMPTED"
      exit 1
    fi
    if [ "$PWRU_FAKE_MODE" = stubborn ]; then
      exit 1
    fi
    rm -f "$state"
    ;;
  info)
    [ "${PWRU_FAKE_MODE:-}" != daemon-fail ]
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fixture/docker"

run_case() {
	local mode=$1 log_content=$2 expected_wait=$3 expected_stop=$4 cleanup=$5 stop_timeout=$6
	local expected_signals=INT
	local state="$fixture/state" output="$fixture/output" signals="$fixture/signals" wait_log="$fixture/wait-log"
	local detach_pending="$fixture/detach-pending" inspect_count="$fixture/inspect-count"
	case "$mode" in
		stuck) expected_signals='INT
KILL' ;;
		stubborn) expected_signals='INT
KILL
KILL' ;;
		signal-exit) expected_signals=INT ;;
	esac
	printf '%s\n%s\n' running 0 >"$state"
	printf '%s\n' "$log_content" >"$fixture/pwru.log"
	: >"$signals"
	rm -f "$fixture/rm-attempted" "$fixture/kill-attempted" "$output" "$wait_log"
	rm -f "$detach_pending" "$inspect_count"
	if PWRU_FAKE_MODE="$mode" PWRU_FAKE_STATE="$state" PWRU_FAKE_LOG="$fixture/pwru.log" \
		PWRU_FAKE_SIGNALS="$signals" PWRU_FAKE_RM_ATTEMPTED="$fixture/rm-attempted" \
		PWRU_FAKE_KILL_ATTEMPTED="$fixture/kill-attempted" PWRU_FAKE_WAIT_LOG="$wait_log" \
		PWRU_FAKE_DETACH_PENDING="$detach_pending" PWRU_FAKE_INSPECT_COUNT="$inspect_count" \
		PWRU_DISABLE_TIMEOUT="${PWRU_DISABLE_TIMEOUT:-false}" \
		PWRU_FAKE_CONTAINER=pwru-proof PWRU_CONTAINER_ID=pwru-proof PATH="$fixture:/usr/bin:/bin" \
		bash -c '
			set -u
			. "$1/pwru-lifecycle.sh"
			wait_status=0
			pwru_wait_for_event "$2" "$3" 1 "127\.0\.0\.1.*->.*127\.0\.0\.1" || wait_status=$?
			test "$wait_status" -eq "$4"
			stop_status=0
			pwru_stop_gracefully "$2" "$8" || stop_status=$?
			test "$stop_status" -eq "$5"
			test "$(cat "$PWRU_FAKE_SIGNALS")" = "$6"
			if [ "${PWRU_DISABLE_TIMEOUT:-false}" = true ] || ! command -v timeout >/dev/null 2>&1; then
				test ! -s "$PWRU_FAKE_WAIT_LOG"
			else
				test "$(cat "$PWRU_FAKE_WAIT_LOG")" = pwru-proof
			fi
			if [ "$7" = true ]; then
				pwru_force_remove "$2" 2
				test ! -e "$PWRU_FAKE_STATE"
			fi
		' bash "$root" pwru-proof "$output" "$expected_wait" "$expected_stop" "$expected_signals" "$cleanup" "$stop_timeout"; then
		:
	else
		printf '%s\n' "pwru lifecycle case $mode failed" >&2
		exit 1
	fi
}

run_case graceful '127.0.0.1:12345 -> 127.0.0.1:18080' 0 0 false 08
PWRU_DISABLE_TIMEOUT=true run_case delayed-graceful '127.0.0.1:12345 -> 127.0.0.1:18080' 0 0 false 2
PWRU_DISABLE_TIMEOUT=false PWRU_STOP_SETTLE_SECONDS=2 run_case delayed-graceful-boundary '127.0.0.1:12345 -> 127.0.0.1:18080' 0 0 false 1
run_case signal-exit '127.0.0.1:12345 -> 127.0.0.1:18080' 0 0 false 1
# Keep the negative cases quick while still proving that a container which
# remains running after the entire settle window fails and is cleaned up.
PWRU_STOP_SETTLE_SECONDS=1 run_case stuck 'pwru started without a packet tuple' 1 2 true 1
PWRU_STOP_SETTLE_SECONDS=1 run_case stubborn 'pwru started without a packet tuple' 1 2 true 1

# Cleanup must refuse a resource with a different owner label and must fail
# closed when the daemon cannot be queried.
printf '%s\n%s\n' running 0 >"$fixture/owner-state"
if PWRU_FAKE_MODE=graceful PWRU_FAKE_STATE="$fixture/owner-state" \
	PWRU_FAKE_CONTAINER=pwru-proof PWRU_CONTAINER_ID=pwru-proof PWRU_FAKE_OWNER=other PWRU_FAKE_LOG="$fixture/pwru.log" \
	PWRU_FAKE_SIGNALS="$fixture/signals" PWRU_OWNER_LABEL=owner PWRU_OWNER_VALUE=expected \
	PATH="$fixture:/usr/bin:/bin" bash -c '. "$1/pwru-lifecycle.sh"; ! pwru_force_remove pwru-proof 1' bash "$root"; then
	:
else
	printf '%s\n' 'owner mismatch was not rejected' >&2
	exit 1
fi
if PWRU_FAKE_MODE=daemon-fail PWRU_FAKE_STATE="$fixture/owner-state" \
	PWRU_FAKE_CONTAINER=pwru-proof PWRU_CONTAINER_ID=pwru-proof PWRU_FAKE_LOG="$fixture/pwru.log" \
	PWRU_FAKE_SIGNALS="$fixture/signals" PATH="$fixture:/usr/bin:/bin" \
	bash -c '. "$1/pwru-lifecycle.sh"; ! pwru_force_remove pwru-proof 1' bash "$root"; then
	:
else
	printf '%s\n' 'daemon failure was not rejected' >&2
	exit 1
fi

if PWRU_FAKE_MODE=inspect-fail-listed PWRU_FAKE_STATE="$fixture/owner-state" \
	PWRU_FAKE_CONTAINER=pwru-proof PWRU_CONTAINER_ID=pwru-proof PWRU_FAKE_LOG="$fixture/pwru.log" \
	PWRU_FAKE_SIGNALS="$fixture/signals" PATH="$fixture:/usr/bin:/bin" \
	bash -c '. "$1/pwru-lifecycle.sh"; ! pwru_force_remove pwru-proof 1' bash "$root"; then
	:
else
	printf '%s\n' 'listed inspect failure was not rejected' >&2
	exit 1
fi
if PWRU_FAKE_MODE=inspect-fail-absent PWRU_FAKE_STATE="$fixture/owner-state" \
	PWRU_FAKE_CONTAINER=pwru-proof PWRU_CONTAINER_ID=pwru-proof PWRU_FAKE_LOG="$fixture/pwru.log" \
	PWRU_FAKE_SIGNALS="$fixture/signals" PATH="$fixture:/usr/bin:/bin" \
	bash -c '. "$1/pwru-lifecycle.sh"; ! pwru_force_remove pwru-proof 1' bash "$root"; then
	:
else
	printf '%s\n' 'inspect failure was incorrectly treated as absence' >&2
	exit 1
fi

printf '%s\n' 'pwru lifecycle behavior checks passed'
