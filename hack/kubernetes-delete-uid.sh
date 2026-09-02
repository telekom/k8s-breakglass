#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Delete one Kubernetes object only when the API server still has the UID
# observed by this invocation. A GET followed by a name-only DELETE is not an
# ownership check: another actor can replace the object between those calls.

kubernetes_delete_uid() {
	[ "$#" -eq 3 ] || return 2
	local kubeconfig=$1 path=$2 uid=$3
	local kubectl_bin=${KUBECTL_BIN:-kubectl}
	[ -n "$uid" ] || return 2
	command -v "$kubectl_bin" >/dev/null 2>&1 || return 2
	command -v jq >/dev/null 2>&1 || return 2
	command -v curl >/dev/null 2>&1 || return 2
	# --arg prevents a future API UID containing JSON metacharacters from
	# changing the DeleteOptions document.
	local delete_options
	delete_options=$(jq -n --arg uid "$uid" \
		'{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}') ||
		return 1
	(
		local proxy_pid proxy_port=${KUBECTL_PROXY_PORT:-18080}
		# shellcheck disable=SC2317 # invoked by the EXIT trap below
		cleanup_proxy() {
			[ -n "${proxy_pid:-}" ] || return 0
			kill "$proxy_pid" 2>/dev/null || true
			wait "$proxy_pid" 2>/dev/null || true
		}
		trap cleanup_proxy EXIT HUP INT TERM
		"$kubectl_bin" --kubeconfig "$kubeconfig" proxy \
			--address=127.0.0.1 --port="$proxy_port" >/dev/null 2>&1 &
		proxy_pid=$!
		for _ in 1 2 3 4 5; do
			if curl --fail --silent --show-error \
				--output /dev/null "http://127.0.0.1:${proxy_port}/api"; then
				break
			fi
			sleep 1
		done
		curl --fail --silent --show-error --request DELETE \
			--header 'Content-Type: application/json' \
			--data "$delete_options" \
			"http://127.0.0.1:${proxy_port}${path}"
	)
}
