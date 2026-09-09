#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Docker containers and networks have immutable IDs and can be removed by
# those IDs. Docker volumes have no removable ID, so test harnesses create
# anonymous volumes through an owner container and remove them with that
# container's immutable ID and Docker's -v operation.

docker_resource_call() {
	local docker_bin=$1
	shift
	if command -v timeout >/dev/null 2>&1 && [ -n "${DOCKER_RESOURCE_TIMEOUT_SECONDS:-}" ]; then
		timeout --foreground "${DOCKER_RESOURCE_TIMEOUT_SECONDS}s" "$docker_bin" "$@"
	else
		"$docker_bin" "$@"
	fi
}

docker_capture_resource_id() {
	[ "$#" -eq 3 ] || return 2
	local docker_bin=$1 kind=$2 name=$3
	case "$kind" in
	container) docker_resource_call "$docker_bin" inspect --format '{{.Id}}' "$name" ;;
	network) docker_resource_call "$docker_bin" network inspect --format '{{.Id}}' "$name" ;;
	*) return 2 ;;
	esac
}

# Register the immutable ID emitted by Docker before any mutable-name lookup.
# A caller that cannot validate this output must leave the resource for runner
# cleanup instead of attempting a name-based removal.
docker_run_detached_with_id() {
	[ "$#" -ge 2 ] || return 2
	local docker_bin=$1 name=$2 id
	shift 2
	id=$(docker_resource_call "$docker_bin" run -d --name "$name" "$@") || return 1
	case "$id" in
		''|*[!0-9a-f]*) return 1 ;;
	esac
	printf '%s\n' "$id"
}

docker_remove_resource_id() {
	[ "$#" -eq 3 ] || return 2
	local docker_bin=$1 kind=$2 id=$3
	[ -n "$id" ] || return 2
	case "$kind" in
	container) docker_resource_call "$docker_bin" rm -f "$id" ;;
	network) docker_resource_call "$docker_bin" network rm "$id" ;;
	*) return 2 ;;
	esac
}

docker_remove_resource_with_volumes() {
	[ "$#" -eq 3 ] || return 2
	local docker_bin=$1 kind=$2 id=$3
	[ "$kind" = container ] || return 2
	[ -n "$id" ] || return 2
	docker_resource_call "$docker_bin" rm -fv "$id"
}

docker_resource_id_exists() {
	[ "$#" -eq 3 ] || return 2
	local docker_bin=$1 kind=$2 id=$3
	case "$kind" in
	container) docker_resource_call "$docker_bin" inspect "$id" >/dev/null 2>&1 ;;
	network) docker_resource_call "$docker_bin" network inspect "$id" >/dev/null 2>&1 ;;
	*) return 2 ;;
	esac
}
