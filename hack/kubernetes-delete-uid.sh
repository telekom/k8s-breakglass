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
	# --arg prevents a future API UID containing JSON metacharacters from
	# changing the DeleteOptions document.
	local delete_options
	delete_options=$(jq -n --arg uid "$uid" \
		'{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}') ||
		return 1
	"$kubectl_bin" --kubeconfig "$kubeconfig" delete --raw "$path" -f - <<<"$delete_options"
}
