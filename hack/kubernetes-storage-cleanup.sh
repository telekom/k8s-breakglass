#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Delete a Pod-backed PVC/PV chain in dependency order. Every DELETE is
# guarded by the UID captured by the caller, and the next object is not
# touched until the previous object is confirmed gone. A failed wait leaves
# the remaining objects in place for inspection.
kubernetes_cleanup_uid_chain() {
	[ "$#" -eq 9 ] || return 2
	local kubeconfig=$1 kubectl_bin=$2 namespace=$3
	local pod_name=$4 pod_uid=$5 pvc_name=$6 pvc_uid=$7 pv_name=$8 pv_uid=$9
	[ -n "$pod_uid" ] || return 0
	if ! kubernetes_delete_uid "$kubeconfig" \
		"/api/v1/namespaces/$namespace/pods/$pod_name" "$pod_uid" >/dev/null 2>&1 ||
		! "$kubectl_bin" --kubeconfig "$kubeconfig" wait --for=delete \
			pod/"$pod_name" --namespace "$namespace" --timeout=120s >/dev/null 2>&1; then
		return 1
	fi
	[ -n "$pvc_uid" ] || return 0
	if ! kubernetes_delete_uid "$kubeconfig" \
		"/api/v1/namespaces/$namespace/persistentvolumeclaims/$pvc_name" "$pvc_uid" >/dev/null 2>&1 ||
		! "$kubectl_bin" --kubeconfig "$kubeconfig" wait --for=delete \
			pvc/"$pvc_name" --namespace "$namespace" --timeout=120s >/dev/null 2>&1; then
		return 1
	fi
	[ -n "$pv_uid" ] || return 0
	if ! kubernetes_delete_uid "$kubeconfig" \
		"/api/v1/persistentvolumes/$pv_name" "$pv_uid" >/dev/null 2>&1 ||
		! "$kubectl_bin" --kubeconfig "$kubeconfig" wait --for=delete \
			pv/"$pv_name" --timeout=120s >/dev/null 2>&1; then
		return 1
	fi
}
