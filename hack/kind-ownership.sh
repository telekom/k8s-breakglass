#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Shared ownership boundary for disposable Kind clusters. An attempted create
# never proves ownership. After a successful create, only the exact immutable
# Docker node IDs observed for the requested label may be removed.

KIND_CLUSTER_CREATED=${KIND_CLUSTER_CREATED:-false}
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
		if ! kind_capture_owned_cluster_identity; then
			return 4
		fi
		# shellcheck disable=SC2034 # exported to the caller's shell
		KIND_CLUSTER_CREATED=true
		return 0
	else
		create_status=$?
	fi
	# A failed create proves no ownership. Leave partial or replacement state
	# untouched, even when it has the exact requested name or label.
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
	[ "$state" -eq 0 ] || return 1
	# Delete only immutable IDs. A name-wide `kind delete` would be racy with a
	# same-name replacement between the ownership check and deletion.
	kind_remove_owned_cluster_resources || return 1
	if kind_owned_cluster_identity_state; then
		return 1
	else
		state=$?
	fi
	[ "$state" -eq 1 ] || return 1
}
