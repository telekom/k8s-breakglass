#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Small, command-line based lifecycle primitives used by the real integration
# proof. Keeping these separate makes timeout and stuck-container behavior
# testable without requiring BPF support.

pwru_wait_for_event() {
	local container=$1 output_file=$2 timeout_seconds=$3 event_pattern=$4
	local state iterations
	case "$timeout_seconds" in
		''|*[!0-9]*) return 1 ;;
	esac
	iterations=$((10#$timeout_seconds * 2))
	[ "$iterations" -gt 0 ] || return 1
	for _ in $(seq 1 "$iterations"); do
		state=$(pwru_docker inspect --format '{{.State.Status}}' "$container") || return 2
		[ "$state" = exited ] && return 3
		if pwru_docker cp "$container:/work/pwru.log" "$output_file" >/dev/null 2>&1 && \
			grep -E -- "$event_pattern" "$output_file" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

pwru_stop_gracefully() {
	local container=$1 timeout_seconds=$2
	local state exit_code iterations settle_seconds settle_iterations ref
	[ -n "${PWRU_CONTAINER_ID:-}" ] || return 1
	ref=$PWRU_CONTAINER_ID
	case "$timeout_seconds" in
		''|*[!0-9]*) return 1 ;;
	esac
	iterations=$((10#$timeout_seconds * 2))
	[ "$iterations" -gt 0 ] || return 1
	state=$(pwru_docker inspect --format '{{.State.Status}}' "$ref") || return 1
	[ "$state" = running ] || return 2
	pwru_validate_owner "$container" || return 1
	pwru_docker kill --signal INT "$ref" >/dev/null || return 1

	# Waiting on the daemon's lifecycle event avoids losing the race between
	# the last inspect poll and a delayed BPF detach. GNU timeout keeps the
	# wait bounded even if pwru never exits; the final inspect below is the
	# source of truth because docker wait's own status is the container's
	# status on some Docker versions.
	if command -v timeout >/dev/null 2>&1 && [ "${PWRU_DISABLE_TIMEOUT:-false}" != true ]; then
		timeout --foreground "${timeout_seconds}s" docker wait "$ref" >/dev/null 2>&1 || true
	else
		# Keep the helper usable in minimal test environments without silently
		# turning this into an unbounded wait.
		for _ in $(seq 1 "$iterations"); do
			state=$(pwru_docker inspect --format '{{.State.Status}}' "$ref") || return 1
			[ "$state" = exited ] && break
			sleep 0.5
		done
	fi

	# A real pwru process can acknowledge SIGINT while its BPF detach is still
	# completing. If docker wait is killed at exactly the timeout boundary, an
	# immediate inspect can therefore observe the old running state even though
	# the container is about to exit. Reconcile that race for a separate,
	# explicitly bounded settle window. A genuinely stuck container still fails
	# closed once this window expires.
	settle_seconds=${PWRU_STOP_SETTLE_SECONDS:-5}
	case "$settle_seconds" in
		''|*[!0-9]*) return 1 ;;
	esac
	settle_iterations=$((10#$settle_seconds * 10))
	[ "$settle_iterations" -gt 0 ] || return 1
	for _ in $(seq 1 "$settle_iterations"); do
		state=$(pwru_docker inspect --format '{{.State.Status}}' "$ref") || return 1
		[ "$state" = exited ] && break
		sleep 0.1
	done
	[ "$state" = exited ] || return 2
	exit_code=$(pwru_docker inspect --format '{{.State.ExitCode}}' "$ref") || return 1
	case "$exit_code" in
		0|130) return 0 ;;
		*) return 3 ;;
	esac
}

pwru_force_remove() {
	local container=$1
	local timeout_seconds=${2:-15}
	local iterations state ref attempted=0
	[ -n "${PWRU_CONTAINER_ID:-}" ] || return 1
	ref=$PWRU_CONTAINER_ID
	# Cleanup is only permitted for the immutable ID captured after creation;
	# falling back to the generated name would reintroduce a takeover race.
	case "$timeout_seconds" in
		''|*[!0-9]*) return 1 ;;
	esac
	iterations=$((10#$timeout_seconds * 2))
	[ "$iterations" -gt 0 ] || return 1
	pwru_docker info >/dev/null 2>&1 || return 1

	# Removal can remain asynchronous while pwru detaches BPF programs. Retry
	# only the exact immutable ID for a bounded window and verify absence after
	# every attempt. A KILL is used only after a failed forced removal; this
	# never broadens cleanup to containers from another invocation.
	for _ in $(seq 1 "$iterations"); do
		if ! pwru_docker inspect "$ref" >/dev/null 2>&1; then
			# Before a delete, an inspect failure is uncertainty, never proof of
			# absence. After a failed remove attempt, the exact-ID list below is
			# the only acceptable asynchronous-absence proof.
			[ "$attempted" -eq 1 ] || return 1
			state=$(pwru_docker container ls --all --no-trunc --filter "id=${ref}" --format '{{.ID}}') || return 1
			[ -z "$state" ] || return 1
			pwru_docker info >/dev/null 2>&1 || return 1
			return 0
		fi
		pwru_validate_owner "$container" || return 1
		attempted=1
		if pwru_docker rm -f "$ref" >/dev/null 2>&1; then
			return 0
		else
			pwru_docker kill --signal KILL "$ref" >/dev/null 2>&1 || true
			if pwru_docker rm -f "$ref" >/dev/null 2>&1; then
				return 0
			fi
		fi
		sleep 0.5
	done
	# A failed rm can complete asynchronously. Confirm absence using the exact
	# immutable ID; a name query is intentionally never used for this decision.
	state=$(pwru_docker container ls --all --no-trunc --filter "id=${ref}" --format '{{.ID}}') || return 1
	[ -z "$state" ] || return 1
	pwru_docker info >/dev/null 2>&1 || return 1
	return 0
}

pwru_docker() {
	local timeout_seconds=${PWRU_DOCKER_TIMEOUT_SECONDS:-30}
	case "$timeout_seconds" in
		''|*[!0-9]*) return 1 ;;
	esac
	[ "$((10#$timeout_seconds))" -gt 0 ] || return 1
	if command -v timeout >/dev/null 2>&1 && [ "${PWRU_USE_DOCKER_TIMEOUT:-false}" = true ] && [ "${PWRU_DISABLE_TIMEOUT:-false}" != true ]; then
		timeout --foreground "${timeout_seconds}s" docker "$@"
	else
		docker "$@"
	fi
}

pwru_validate_owner() {
	local container=$1 owner ref
	ref=${PWRU_CONTAINER_ID:-$container}
	[ -n "${PWRU_OWNER_LABEL:-}" ] || return 0
	owner=$(pwru_docker inspect --format "{{index .Config.Labels \"${PWRU_OWNER_LABEL}\"}}" "$ref") || return 1
	[ "$owner" = "${PWRU_OWNER_VALUE:-}" ]
}
