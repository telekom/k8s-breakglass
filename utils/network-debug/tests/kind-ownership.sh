#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# The integration harness uses a generated run-scoped cluster name. A failed
# `kind create` can still leave a partial cluster, so creation is an explicit
# ownership transition: an absent preflight name plus an attempted create owns
# only that exact name for cleanup. A pre-existing name is never touched.

kind_cluster_state() {
	local clusters
	clusters=$("$KIND_BIN" get clusters 2>/dev/null) || return 2
	if printf '%s\n' "$clusters" | grep -Fx "$KIND_CLUSTER_NAME" >/dev/null 2>&1; then
		return 0
	fi
	return 1
}

kind_cluster_resources_state() {
	local state artifacts
	if kind_cluster_state; then
		return 0
	else
		state=$?
	fi
	[ "$state" -eq 1 ] || return 2
	# A failed kind bootstrap can leave labeled node containers even when
	# `kind get clusters` no longer lists the cluster. Inspecting only this
	# exact generated name lets us remove those partial artifacts without
	# touching any other cluster.
	[ -n "${DOCKER_BIN:-}" ] || return 1
	artifacts=$("$DOCKER_BIN" ps -a --filter "label=io.x-k8s.kind.cluster=$KIND_CLUSTER_NAME" --format '{{.Names}}' 2>/dev/null) || return 2
	[ -n "$artifacts" ] && return 0
	return 1
}

kind_create_owned_cluster() {
	local state create_status
	if kind_cluster_resources_state; then
		state=0
	else
		state=$?
	fi
	case "$state" in
		0) return 2 ;;
		1) ;;
		*) return 3 ;;
	esac

	KIND_CLUSTER_CREATE_ATTEMPTED=true
	if "$KIND_BIN" create cluster --name "$KIND_CLUSTER_NAME" --image "$KIND_NODE_IMAGE" \
		--kubeconfig "$KUBECONFIG_FILE" --wait 120s; then
		# shellcheck disable=SC2034 # exported to the caller's shell
		KIND_CLUSTER_CREATED=true
		return 0
	else
		create_status=$?
	fi

	# The preflight proved this exact name absent. If kind left a partial
	# cluster, delete and verify only this run-scoped name. If inspection fails,
	# fail closed rather than guessing ownership.
	if kind_cluster_resources_state; then
		state=0
	else
		state=$?
	fi
	if [ "$state" -eq 0 ]; then
		if ! "$KIND_BIN" delete cluster --name "$KIND_CLUSTER_NAME"; then
			return 4
		fi
		if kind_cluster_resources_state; then
			state=0
		else
			state=$?
		fi
		[ "$state" -eq 1 ] || return 4
	elif [ "$state" -eq 2 ]; then
		return "$create_status"
	fi
	return "$create_status"
}

kind_cleanup_owned_cluster() {
	local state
	[ "${KIND_CLUSTER_CREATE_ATTEMPTED:-false}" = true ] || return 0
	if kind_cluster_resources_state; then
		state=0
	else
		state=$?
	fi
	if [ "$state" -eq 0 ]; then
		"$KIND_BIN" delete cluster --name "$KIND_CLUSTER_NAME" || return 1
		if kind_cluster_resources_state; then
			state=0
		else
			state=$?
		fi
		[ "$state" -eq 1 ] || return 1
	elif [ "$state" -eq 2 ]; then
		return 1
	fi
	return 0
}
