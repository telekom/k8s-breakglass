#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# The integration harness uses a generated run-scoped cluster name. A failed
# `kind create` can still leave a partial cluster, but an attempted create does
# not prove ownership: another actor can claim the name while it is failing.
# Cleanup therefore requires a successful create and the exact Docker node
# identities observed immediately afterwards. A safe leak is preferable to
# deleting a foreign replacement or partial state.

KIND_CLUSTER_OWNER_IDS=${KIND_CLUSTER_OWNER_IDS:-}

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
	# `kind get clusters` no longer lists the cluster. They are evidence of
	# residual state, not proof that this process owns it.
	[ -n "${DOCKER_BIN:-}" ] || return 1
	artifacts=$("$DOCKER_BIN" ps -a --filter "label=io.x-k8s.kind.cluster=$KIND_CLUSTER_NAME" --format '{{.ID}}' 2>/dev/null) || return 2
	[ -n "$artifacts" ] && return 0
	return 1
}

kind_capture_owned_cluster_identity() {
	local ids
	[ -n "${DOCKER_BIN:-}" ] || return 1
	ids=$("$DOCKER_BIN" ps -a --no-trunc --filter "label=io.x-k8s.kind.cluster=$KIND_CLUSTER_NAME" --format '{{.ID}}' 2>/dev/null | LC_ALL=C sort) || return 2
	[ -n "$ids" ] || return 1
	KIND_CLUSTER_OWNER_IDS=$ids
}

kind_owned_cluster_identity_state() {
	local ids
	[ -n "${DOCKER_BIN:-}" ] || return 2
	[ -n "${KIND_CLUSTER_OWNER_IDS:-}" ] || return 1
	ids=$("$DOCKER_BIN" ps -a --no-trunc --filter "label=io.x-k8s.kind.cluster=$KIND_CLUSTER_NAME" --format '{{.ID}}' 2>/dev/null | LC_ALL=C sort) || return 2
	[ -n "$ids" ] && [ "$ids" = "$KIND_CLUSTER_OWNER_IDS" ] && return 0
	return 1
}

kind_remove_owned_cluster_resources() {
	local id
	[ -n "${DOCKER_BIN:-}" ] || return 1
	while IFS= read -r id; do
		[ -n "$id" ] || continue
		"$DOCKER_BIN" rm -f "$id" >/dev/null 2>&1 || return 1
	done <<< "$KIND_CLUSTER_OWNER_IDS"
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

	if "$KIND_BIN" create cluster --name "$KIND_CLUSTER_NAME" --image "$KIND_NODE_IMAGE" \
		--kubeconfig "$KUBECONFIG_FILE" --wait 120s; then
		# A successful create is still not enough to authorize name-wide
		# deletion: retain the immutable node IDs that prove which resources
		# this invocation created.
		if ! kind_capture_owned_cluster_identity; then
			return 4
		fi
		# shellcheck disable=SC2034 # exported to the caller's shell
		KIND_CLUSTER_CREATED=true
		return 0
	else
		create_status=$?
	fi

	# A failed create proves no ownership. Leave any partial state untouched;
	# in particular, do not delete a same-name cluster created by another actor.
	return "$create_status"
}

kind_cleanup_owned_cluster() {
	local state
	[ "${KIND_CLUSTER_CREATED:-false}" = true ] || return 0
	if kind_owned_cluster_identity_state; then
		state=0
	else
		state=$?
	fi
	if [ "$state" -eq 0 ]; then
		# Remove only the immutable container IDs captured after our successful
		# create. A name-wide `kind delete` would be racy with a same-name
		# replacement between the ownership check and deletion.
		kind_remove_owned_cluster_resources || return 1
		if kind_owned_cluster_identity_state; then
			state=0
		else
			state=$?
		fi
		[ "$state" -eq 1 ] || return 1
	else
		return 1
	fi
	return 0
}
