#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Small, command-line based lifecycle primitives used by the real integration
# proof. Keeping these separate makes timeout and stuck-container behavior
# testable without requiring BPF support.

pwru_wait_for_event() {
	local container=$1 output_file=$2 timeout_seconds=$3 event_pattern=$4
	local state
	for _ in $(seq 1 "$((timeout_seconds * 2))"); do
		state=$(docker inspect --format '{{.State.Status}}' "$container") || return 2
		[ "$state" = exited ] && return 3
		if docker cp "$container:/work/pwru.log" "$output_file" >/dev/null 2>&1 && \
			grep -E -- "$event_pattern" "$output_file" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

pwru_stop_gracefully() {
	local container=$1 timeout_seconds=$2
	local state exit_code
	docker kill --signal INT "$container" >/dev/null || return 1
	for _ in $(seq 1 "$((timeout_seconds * 2))"); do
		state=$(docker inspect --format '{{.State.Status}}' "$container") || return 1
		[ "$state" = exited ] && break
		sleep 0.5
	done
	[ "$state" = exited ] || return 2
	exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$container") || return 1
	case "$exit_code" in
		0|130) return 0 ;;
		*) return 3 ;;
	esac
}

pwru_force_remove() {
	local container=$1
	if docker inspect "$container" >/dev/null 2>&1; then
		if ! docker rm -f "$container" >/dev/null 2>&1; then
			# A daemon can report an in-use process even after rm -f. Escalate
			# once, then retry; never claim cleanup without the exact-name check.
			docker kill --signal KILL "$container" >/dev/null 2>&1 || true
			docker rm -f "$container" >/dev/null 2>&1 || true
		fi
		# The second attempt also handles a slow daemon whose first rm returned
		# before the container disappeared.
		if docker inspect "$container" >/dev/null 2>&1; then
			docker rm -f "$container" >/dev/null 2>&1 || true
		fi
	fi
	if docker inspect "$container" >/dev/null 2>&1; then
		return 1
	fi
	# Absence is only a proof when the daemon was reachable for the inspect.
	docker info >/dev/null 2>&1 || return 1
}
